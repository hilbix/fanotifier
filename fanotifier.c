#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/fanotify.h>

#if 0
#define	DP(X)	do { debugset(__FILE__, __LINE__, __FUNCTION__); debugprintf X; } while (0)
static void
debugset(const char *file, int line, const char *fn)
{
  fprintf(stderr, "[[%s:%d:%s", file, line, fn);
}
static void
debugprintf(const char *s, ...)
{
  va_list	list;

  va_start(list, s);
  vfprintf(stderr, s, list);
  va_end(list);
  fprintf(stderr, "]]\n");
  fflush(stderr);
}
#else
#define	DP(X)	xDP(X)
#endif
#define	xDP(X)	do { ; } while (0)

enum
  {
    SYNTHETIC_PWD	= 1,
    SYNTHETIC_CMD	= 2,
    SYNTHETIC_ARGS	= 4,
    SYNTHETIC_PPID	= 8,
    SYNTHETIC_TIME	= 16,
    SYNTHETIC_ALLOW	= 32,
    SYNTHETIC_UNKNOWN	= 64,
  };

#define	MODES_ALL	(FAN_ACCESS|FAN_OPEN|FAN_MODIFY|FAN_CLOSE_WRITE|FAN_CLOSE_NOWRITE)
#define	PERMS_ALL	(FAN_OPEN_PERM|FAN_ACCESS_PERM)

static struct _modes
  {
    const char	*name;
    int		synthetic, mode, perm;
  } modes[] =
  {
    { "ALL",	 	0, MODES_ALL,   	},
    { "ACCESS", 	0, FAN_ACCESS,  	FAN_ACCESS_PERM	},
    { "OPEN",   	0, FAN_OPEN,    	FAN_OPEN_PERM	},
    { "MODIFY", 	0, FAN_MODIFY,  	},
    { "CLOSE_W", 	0, FAN_CLOSE_WRITE,	},
    { "CLOSE_R", 	0, FAN_CLOSE_NOWRITE,	},
    { "OVERFLOW",	0, FAN_Q_OVERFLOW	},
    { "CMD",		SYNTHETIC_CMD },
    { "PWD",		SYNTHETIC_PWD },
    { "ARGS",		SYNTHETIC_ARGS },
    { "PPID",		SYNTHETIC_PPID },
    { "TIME",		SYNTHETIC_TIME },
    { "ALLOW",		SYNTHETIC_ALLOW },
    { "UNKNOWN",	SYNTHETIC_UNKNOWN },
    { 0 }
  };

static int	mode_disable, perm_disable, synth_disable;
static unsigned	pid_max;
static unsigned	flags;
static int	fa = -1;
static const char *arg0;

#define	PID_IGNORED	((struct _pids *)1)

static struct _pids
  {
    unsigned	count, counter;
    unsigned	ppid;
    const char	*pwd, *cmd, *args;
    unsigned long long	start;
  }	**pids;

struct usage
  {
    const char	*desc;
    int		flag;
  } usages[] =
  {
#define	FLAG_MOUNT					0x0000
    { "path is complete mount point",			FLAG_MOUNT },
#define	FLAG_FILE					0x0001
    { "path is a file",					FLAG_FILE },
#define	FLAG_DIR					0x0002
    { "path must be directory",				FLAG_DIR },
#define	FLAG_DIR_CHILD					0x0003
    { "directory with monitoring of directory childs",	FLAG_DIR_CHILD },
#define	FLAG_NO_FAN_NODIR				0x0004
    { "do not monitor directories",			FLAG_NO_FAN_NODIR },
#define	FLAG_VERBOSE					0x0008
    { "verbose mode",					FLAG_VERBOSE },
#define	FLAG_UNBUFFERED					0x0010
    { "unbuffered output",				FLAG_UNBUFFERED },
#define	FLAG_BLOCKING					0x0020
    { "block processes (correct synthetic events)",	FLAG_BLOCKING },
#define	FLAG_FAN_UNLIMITED_QUEUE			0x0040
    { "unlimited fanotify queue",			FLAG_FAN_UNLIMITED_QUEUE },
#define	FLAG_FAN_UNLIMITED_MARKS			0x0080
    { "unlimited number of monitors",			FLAG_FAN_UNLIMITED_MARKS },
#define	FLAG_FOLLOW_LINKS				0x0100
    { "follow softlinks on arguments",			FLAG_FOLLOW_LINKS },
#define	FLAG_NO_QUOTE					0x0200
    { "do not quote 3rd column",			FLAG_NO_QUOTE },
#define	FLAG_HUMAN					0x0400
    { "output empty separation lines (for humans)",	FLAG_HUMAN },
#define	FLAG_DEBUG					0x8000
    { "enable debugging (skips some errors)",		FLAG_DEBUG },
#define	FLAG_ALL					0x87ff
    { 0 }
  }, *usg = usages;

static void
vOOPS(int e, const char *s, va_list list, int nonfatal)
{
  if (!nonfatal && fa>=0)
    close(fa);			/* just to be sure nothing hangs */

  fprintf(stderr, "OOPS: ");
  vfprintf(stderr, s, list);
  if (e)
    fprintf(stderr, ": %s", strerror(e));
  fprintf(stderr, "\n");
  fflush(stderr);

  if (nonfatal)
    return;

#if 1
  exit(23);
#endif
  abort();
  for(;;);
}

static void
OOPS(const char *s, ...)
{
  va_list	list;

  va_start(list, s);
  vOOPS(errno, s, list, flags & FLAG_DEBUG);
  va_end(list);
}

static void
FATAL(const char *s, ...)
{
  va_list	list;

  va_start(list, s);
  vOOPS(errno, s, list, 0);
  va_end(list);
}

static void *
re_alloc(void *ptr, size_t len)
{
  if (!len)
    len = 1;
  ptr = realloc(ptr, len);
  if (!ptr)
    FATAL("out of memory");
  return ptr;
}

static void *
alloc(size_t len)
{
  void	*ptr;

  ptr	= re_alloc(NULL, len);
  memset(ptr, 0, len);
  return ptr;
}

static void *
myfree(const void *ptr)
{
  if (ptr)
    free((void *)ptr);
  return 0;
}

static void *
shrinkalloc(void *ptr, size_t len)
{
  void	*ret;

  if (!len)
    len	= 1;
  ret = realloc(ptr, len);
  return ret ? ret : ptr;
}

static char *
mystrdup(const char *s)
{
  char	*ret;

  ret	= strdup(s);
  if (!ret)
    FATAL("out of memory");
  return ret;
}

#define	DESPARATE(X)	int ret, loops; for (loops=100000; --loops>=0 && (ret=(X))<0 && errno==EINTR; ); return ret;

static int myclose(int fd) { DESPARATE(close(fd)); }
static int myread(int fd, void *ptr, size_t max) { DESPARATE(read(fd, ptr, max)); }
static void mywrite(int fd, const void *ptr, size_t max)
{
  int pos;

  for (pos=0; pos<max; )
    {
      int	ok;

      ok = write(fd, ((const char *)ptr)+pos, max-pos);
      if (ok<0 && errno==EINTR)
	continue;
      if(ok<=0)
	FATAL("cannot write to %d", fd);
      pos += ok;
    }
}

static char *
myreadin(char *buf, size_t max, const char *name)
{
  int fd, got;

  if ((fd = open(name, O_RDONLY))<0)
    return 0;
  for (got=0; got<max; )
    {
      int len;

      len = myread(fd, buf+got, max-got);
      if (len<0)
	return 0;
      if (len)
	{
	  got += len;
	  continue;
	}
      buf[got] = 0;
      if (myclose(fd))
	return 0;
      return buf;
    }
  OOPS("buffer too small to read %s", name);
  return 0;
}

static char *
readin(char *buf, size_t max, const char *name)
{
  if (!myreadin(buf, max, name))
    FATAL("cannot read %s", name);
  return buf;
}

static char *
myreadlink(const char *link)
{
  static int	size = PATH_MAX;	/* adapt to workload	*/
  int		i;

  for (i=5; --i;)
    {
      struct stat	st;
      ssize_t		ok;
      char		*buf;

      buf	= alloc(size);
      ok	= readlink(link, buf, size);
      if (ok<0)
	return myfree(buf);
      if (ok<size)
        {
	  buf[ok]	= 0;
	  return shrinkalloc(buf, ok+1);
        }
      myfree(buf);
      if (lstat(link, &st))
        return 0;

      size = PATH_MAX + st.st_size;
    }
  OOPS("weird link size: %s", link);
  return 0;
}

static char *
readall(int fd, size_t *len)
{
  char		*buf;
  size_t	max;
  int		got;

  *len	= 0;
  buf	= 0;
  max	= BUFSIZ;
  for (got=0;; )
    {
      int	tmp;

      max	+= got;
      buf	= re_alloc(buf, max);
      tmp	= myread(fd, buf+got, max-got);
      if (tmp<0)
	return myfree(buf);
      if (!tmp)
	break;
      got += tmp;
    }
  return shrinkalloc(buf, *len=got);
}

static char *
readargs(const char *name)
{
  char		*buf, *out;
  size_t	len;
  int		fd, need, i, pos;

  if ((fd = open(name, O_RDONLY))<0)
    return mystrdup("error");

  buf	= readall(fd, &len);
  if (myclose(fd) || !buf)
    return mystrdup("error");

  need	= 3;
  for (i=len; --i>=0; )
    {
      switch (buf[i])
	{
	case 0:
	  need++;
	case '\\':
	case '\"':
	  need++;
	  break;
	}
      need++;
   }

  out	= alloc(need);
  pos	= 0;
  for (i=0; i<len; i++)
    {
      if (i)
        out[pos++]	= ' ';
      out[pos++]	= '\"';
      for (; i<len && buf[i]; i++)
	{
	  switch (buf[i])
	    {
	    case '\\':
	    case '\"':
	      out[pos++]	= '\\';
	      break;
	    }
	  out[pos++]	= buf[i];
	}
      out[pos++]	= '\"';
    }
  out[pos++]	= 0;
  if (pos>need)
    FATAL("internal error in readargs(): %s: got %d, calulated=%d)", name, pos, need);
  myfree(buf);
  return out;
}

static char *
strip(char *s)
{
  char		*p;
  size_t	len = strlen(s);

  if (!s)
    FATAL("cannot strip() NULL");
  while (len && isspace(s[--len]))
    s[len] = 0;
  for (p=s; *p && isspace(*p); p++);
  if (s!=p)
    memmove(s, p, strlen(p)+1);
  return s;
}

static unsigned long
parseul(const char *s)
{
  char *end;
  unsigned long ul;

  if (!s)
    FATAL("NULL argument instead of unsigned long integer");
  ul = strtoul(s, &end, 0);
  if (!end || *end)
    FATAL("argument cannot be parsed as unsigned long integer: %s (%s)", s, end);
  return ul;
}

static unsigned
ul2u(unsigned long ul)
{
  unsigned u = ul;

  if (ul-u)
    FATAL("%lu does not fit in data type", ul);
  return u;
}

static const char *
myvsnprintf(char *buf, size_t max, const char *format, va_list olist)
{
  static int	size = PATH_MAX;	/* adapt to workload	*/
  va_list	list;

  if (buf)
    {
      int	len;

      va_copy(list, olist);
      len = vsnprintf(buf, max, format, list);
      va_end(list);
      if (len<0 || len>=max-1 /* be sure in case NUL is not counted */)
        FATAL("buffer of size %llu too small for format: %s", (unsigned long long)max, format);
      return buf;
    }

  if (max<PATH_MAX)
    max	= PATH_MAX;
  /* buf==NULL	*/
  for (;;)
    {
      int	len;

      buf	= re_alloc(buf, size);

      va_copy(list, olist);
      len = vsnprintf(buf, size, format, list);
      va_end(list);
      
      if (len<0)
	FATAL("sprintf failed for format %s", format);
      if (len<size-1)
	return shrinkalloc(buf, len+1);

      size += max;
    }
}

static const char *
mysnprintf(char *buf, size_t max, const char *format, ...)
{
  va_list	list;
  const char	*ret;

  va_start(list, format);
  ret	= myvsnprintf(buf, max, format, list);
  va_end(list);
  return ret;
}

static void
str_set(const char **str, const char *val)
{
  if (*str)
    myfree(*str);
  *str = val;
}

static void
proc_reset(struct _pids *p)
{
  str_set(&p->pwd, NULL);
  str_set(&p->cmd, NULL);
  p->ppid	= 0;
  p->count	= 0;
  p->counter	= 0;
}

static unsigned
get_pid_max(void)
{
  char	buf[BUFSIZ];

  return ul2u(parseul(strip(readin(buf, sizeof buf, "/proc/sys/kernel/pid_max"))));
}

static void
endis(const char *event, int enable)
{
  struct _modes *m;

  for (m=modes; m->name; m++)
    if (!strcmp(event, m->name))
      {
        if (enable)
	  {
	    mode_disable &= ~m->mode;
	    perm_disable &= ~m->perm;
	    synth_disable &= ~m->synthetic;
	  }
	else
	  {
	    mode_disable |= m->mode;
	    perm_disable |= m->perm;
	    synth_disable |= m->synthetic;
	  }
	return;
      }

  if (usg)
    {
      fprintf(stderr, "Usage: %s [+|-]event|-PID|+flags|path..", arg0);
      fprintf(stderr, "\n\tEvent values:\n");
      for (m=modes; m->name && ! m->synthetic; m++)
        fprintf(stderr, "\t%s", m->name);
      fprintf(stderr, "\n\tSynthetic events:\n");
      for (; m->name; m++)
        fprintf(stderr, "\t%s", m->name);
      fprintf(stderr, "\n\tFlags values (do logical or to set more than one):\n");
      for (; usg->desc; usg++)
        fprintf(stderr, "\t%+7d\t%#7x\t%s\n", usg->flag, usg->flag, usg->desc);
      usg = 0;
    }
  OOPS("cannot %s unknown event '%s'", enable ? "enable" : "disable", event);
}

static void
setflags(unsigned long flag)
{
  flags = flag;
  if (flags & ~FLAG_ALL)
    OOPS("unsupported flags: %lx", flags & ~FLAG_ALL);
}

static void
ignorepids(void (*fn)(unsigned long))
{
  DIR		*dp;
  struct dirent	*de;

  if ((dp=opendir("/proc"))==NULL)
    {
      OOPS("cannot open %s", "/proc");
      return;
    }
  while (errno=0, (de=readdir(dp))!=NULL)
    if (isdigit(de->d_name[0]))
      {
        unsigned long pid;

        pid = parseul(de->d_name);
        if (!pid)
          OOPS("PID=0 in %s", "/proc");
        else
          (*fn)(pid);
      }
  closedir(dp);
  if (errno)
    OOPS("failed to read %s", "/proc");
}

static void
ignorepid(unsigned long pid)
{
  if (!pid)
    {
      ignorepids(ignorepid);
      return;
    }

  if (!pids)
    {
      pid_max	= get_pid_max();
      pids	= alloc(pid_max * sizeof *pids);
    }
  if (pid>=pid_max)
    OOPS("process id %lu out of bounds, max is %u", pid, pid_max);
  else
    pids[pid] = PID_IGNORED;
}

static int
add_path(const char *name)
{
  int	flag, mask;

  if (*name=='+' || *name=='-')
    return 1;

  if (fa<0)
    fa	= fanotify_init(((flags & FLAG_BLOCKING) ? FAN_CLASS_PRE_CONTENT : FAN_CLASS_NOTIF)
			| FAN_CLOEXEC
			| ((flags & FLAG_FAN_UNLIMITED_QUEUE) ? FAN_UNLIMITED_QUEUE : 0)
			| ((flags & FLAG_FAN_UNLIMITED_MARKS) ? FAN_UNLIMITED_MARKS : 0)
			,
			O_LARGEFILE
			| O_CLOEXEC
			| ((flags & FLAG_BLOCKING) ? O_RDWR : O_RDONLY)
		       );
  if (fa<0)
    FATAL("fanotify_init() failed");

  flag		= FAN_MARK_ADD;
  mask		= MODES_ALL & (~mode_disable);
  if (flags & FLAG_BLOCKING)
    mask	= PERMS_ALL & (~perm_disable);
  if (!(flags & FLAG_NO_FAN_NODIR))
    mask	|= FAN_ONDIR;
  switch (flags & FLAG_DIR_CHILD)
    {
    case FLAG_DIR_CHILD:	mask	|= FAN_EVENT_ON_CHILD;	break;
    case FLAG_MOUNT:		flag	|= FAN_MARK_MOUNT;	break;
    }
  if (flags & FLAG_DIR)
    flag	|= FAN_MARK_ONLYDIR;
  if (!(flags & FLAG_FOLLOW_LINKS))
    flag	|= FAN_MARK_DONT_FOLLOW;

  if (fanotify_mark(fa, flag, mask, AT_FDCWD, name))
    OOPS("cannot monitor %s", name);

  return 0;
}

static void
options(const char * const *ptr)
{
  for (; *ptr; ptr++)
    if (add_path(*ptr))
      switch (ptr[0][1])
        {
          case '0': case '1': case '2': case '3': case '4':
          case '5': case '6': case '7': case '8': case '9':
            (**ptr=='+' ? setflags : ignorepid)(parseul(*ptr+1));
            break;

          default:
            endis(*ptr+1, **ptr=='+');
	    break;
        }
}

static void
escape(const char *s)
{
  int	spc;
  char	c;

  spc	= 0;
  for (;;)
    {
      switch (c = *s++)
        {
        case 0:
  	  while (spc--)
  	    printf("\\40");
	  return;

	case ' ':
	  spc++;
	  continue;
	}

      for (; spc; spc--)
	putchar(' ');

      switch (c)
	{
	case '\a':	c = 'a'; break;
	case '\b':	c = 'b'; break;
	case '\f':	c = 'f'; break;
	case '\n':	c = 'n'; break;
	case '\r':	c = 'r'; break;
	case '\t':	c = 't'; break;
	case '\v':	c = 'v'; break;
	case '\\':	c = '\\'; break;

	default:
	  if (isprint(c))
	    {
	      putchar(c);
	      continue;
	    }
	case '\'':	/* ANSI $'xxxx'	*/
	  printf("\\x%02x", c);
	  continue;
        }
      putchar('\\');
      putchar(c);
    }
}

static void
vev(const char *ev, long pid, const char *s, va_list list)
{
  printf("%s\t%ld\t", ev, pid);
  if (flags & FLAG_NO_QUOTE)
    vprintf(s, list);
  else
    {
      const char	*buf;

      buf	= myvsnprintf(NULL, BUFSIZ, s, list);
      escape(buf);
      myfree(buf);
    }
  putchar('\n');
}

#if 0
static void
ev(const char *ev, long pid, const char *s, ...)
{
  va_list	list;

  va_start(list, s);
  vev(ev, pid, s, list);
  va_end(list);
}
#endif

static void
verbose(const char *ev, long pid, const char *s, ...)
{
  va_list	list;

  if (!(flags & FLAG_VERBOSE))
    return;
  va_start(list, s);
  vev(ev, pid, s, list);
  va_end(list);
}

static void
print_event(int synthetic, int mask, const char *event, const struct fanotify_event_metadata *ptr, const char *name, ...)
{
  va_list	list;

  if (!synthetic && !mask)
    return;
  000; /* XXX TODO XXX: escapes, ignores, etc.	*/
  va_start(list, name);
  vev(event, (long)ptr->pid, name, list);
  va_end(list);
}

static int
synthetic_u(int synth, unsigned *var, unsigned val)
{
  if (*var==val)
    return 0;
  *var = val;
  return synth;
}

/* Set a syntetic, returns 0 if no change	*/
static int
synthetic_s(int synth, const char **var, const char *val_allocated)
{
  if (!val_allocated || (*var && !strcmp(*var, val_allocated)))
    return myfree(val_allocated), 0;
  myfree(*var);
  *var = val_allocated;
  return synth;
}

static void
emptyline(void)
{
  if (flags & FLAG_HUMAN)
    putchar('\n');
}

static int
synthetic(struct _pids *p, unsigned pid)
{
  char			tmp[PATH_MAX], buf[BUFSIZ], *s, *state;
  unsigned long long	start;
  int			ppid, ret;

  xDP(("() pid=%u", pid));
  ret	= 0;
  if (!myreadin(buf, sizeof buf, mysnprintf(tmp, sizeof tmp, "/proc/%u/stat", pid)))
    {
      verbose("(OOPS)", pid, "cannot read %s", tmp);
      proc_reset(p);
      return 0;
    }
  /* WTF? /proc/self/stat's 2nd field (comm) can contain any character, like SPC or a faked /proc/self/stat line.
   * Hunt for the last non-digit.  That's the start of the 3rd field (state)
   */
  state = 0;
  for (s=buf; *s; s++)
    switch (*s)
      {
      default:
	state = s;

      case ' ': case '-': case '\n':
      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
        break;
      }
  if (!state || 2 != sscanf(state, "%*c %d %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu ", &ppid, &start))
    {
      OOPS("cannot parse %s: '%s'", tmp, state);
      return 0;
    }

  if (p->start != start)
    {
      proc_reset(p);
      p->start = start;
      emptyline();
      ret	|= SYNTHETIC_TIME;
    }
  else
    p->count	= p->counter++ >> 2;	/* just do something like a slow quadratic backoff	*/

  ret	|= synthetic_u(SYNTHETIC_PPID, &p->ppid, ppid);
  ret	|= synthetic_s(SYNTHETIC_CMD,  &p->cmd,  myreadlink(mysnprintf(tmp, sizeof tmp, "/proc/%u/exe", pid)));
  ret	|= synthetic_s(SYNTHETIC_PWD,  &p->pwd,  myreadlink(mysnprintf(tmp, sizeof tmp, "/proc/%u/cwd", pid)));
  ret	|= synthetic_s(SYNTHETIC_ARGS, &p->args, readargs(mysnprintf(tmp, sizeof tmp, "/proc/%u/cmdline", pid)));

  if (ret & SYNTHETIC_ARGS)
    p->counter	= 0;

  DP(("() counter=%d ret=%x", p->counter, ret));
  return ret;
}

static void
print_events(const struct fanotify_event_metadata *ptr)
{
  char		fdname[32], name[PATH_MAX];
  int		len, have, synth;
  unsigned	bits;
  struct _modes *m;
  struct _pids	*p;

  len	 = 0;
  if (ptr->fd>=0)
    {
      len	= readlink(mysnprintf(fdname, sizeof fdname, "%d", ptr->fd), name, (sizeof name)-1);
      if (len<0)
        {
          OOPS("cannot readlink %d", ptr->fd);
          len = 0;
        }
    }
  name[len] = 0;

  synth	= 0;
  p	= 0;
  if (ptr->pid>0 && ptr->pid<pid_max && PID_IGNORED != (p = pids[ptr->pid]))
    {
      if (!p)
	p	= pids[ptr->pid]	= alloc(sizeof *p);
      if (!p->count--)
	synth	= synthetic(p, ptr->pid);
    }

  if (ptr->mask & PERMS_ALL)
    {
      struct fanotify_response r;
 
      if (flags & FLAG_VERBOSE)
        print_event(SYNTHETIC_ALLOW, 0, "ALLOW", ptr, "%s", name);
      r.fd		= ptr->fd;
      r.response	= FAN_ALLOW;
      mywrite(fa, &r, sizeof r);
    }

  if (p == PID_IGNORED)
    return;	/* ignored by PID	*/

  if (synth)
    {
      print_event(synth&SYNTHETIC_CMD,  0, "CMD",  ptr, "%s", p->cmd);
      print_event(synth&SYNTHETIC_ARGS, 0, "ARGS", ptr, "%s", p->args);
      print_event(synth&SYNTHETIC_PWD,  0, "PWD",  ptr, "%s", p->pwd);
      print_event(synth&SYNTHETIC_PPID, 0, "PPID", ptr, "%u", p->ppid);
      print_event(synth&SYNTHETIC_TIME, 0, "TIME", ptr, "%llu", p->start);
    }

  have = 0;
  for (m=modes+1; m->name; m++)
    if ((bits=ptr->mask & (m->mode|m->perm))!=0)
      {
        print_event(0, bits, m->name, ptr, "%s", name);
        have = 1;
      }

  if (!have)
    print_event(SYNTHETIC_UNKNOWN, 0, "(UNKNOWN)", ptr, "%s", name);

  if (flags & FLAG_UNBUFFERED && fflush(stdout))
    FATAL("STDOUT went away");
}

static int
monitor(void)
{
  struct fanotify_event_metadata	ev[1000];
  struct fanotify_event_metadata const	*ptr;
  int					len;

  if (chdir("/proc/self/fd"))
    FATAL("cannot cd %s", "/proc/self/fd");

  len = read(fa, ev, sizeof ev);
  if (len<0 && errno!=EAGAIN && errno!=EINTR)
    {
      OOPS("read error on fanotify FD %d", fa);
      return 0;
    }
  if (len<=0)
    return 1;

  for (ptr=ev; FAN_EVENT_OK(ptr, len);  ptr = FAN_EVENT_NEXT(ptr, len))
    {
      if (ptr->vers != FANOTIFY_METADATA_VERSION)
        FATAL("fanotify communication error, version mismatch");

      if (ptr->fd<0)
	{
          print_event(0, FAN_Q_OVERFLOW, "OVERFLOW", ptr, NULL);
	  continue;
	}
      print_events(ptr);
      myclose(ptr->fd);
    }
  return 1;
}

int
main(int argc, const char * const *argv)
{
  arg0 = argv[0];
  ignorepid(getpid());
  options(argv+1);
  if (fa<0)
    add_path(".");
  while (monitor());
  myclose(fa);
  return 0;
}
