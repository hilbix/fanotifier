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
    { "CWD",		1 },
    { "PROC",		2 },
    { "PPID",		3 },
    { 0 }
  };

static int	mode_disable, perm_disable, synth_disable;
static unsigned	pid_max;
static unsigned char	*pids;
static unsigned	flags;
static int	fa = -1;
static const char *arg0;

#define	FLAG_ALL			0x81ff

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
#define	FLAG_DEBUG					0x8000
    { "enable debugging (skips some errors)",		FLAG_DEBUG },
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

  exit(23);
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
alloc(size_t len)
{
  void *ptr;

  if (!len)
    len = 1;
  ptr = malloc(len);
  if (!ptr)
    FATAL("Out of memory");
  memset(ptr, 0, len);
  return ptr;
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
readin(char *buf, size_t max, const char *name)
{
  int fd, got;

  if ((fd = open(name, O_RDONLY))<0)
    FATAL("cannot open %s", name);
  for (got=0; got<max; )
    {
      int len;

      len = myread(fd, buf+got, max-got);
      if (len<0)
        FATAL("cannot read %s", name);
      if (len)
	{
	  got += len;
	  continue;
	}
      buf[got] = 0;
      if (myclose(fd))
	FATAL("cannot close %s", name);
      return buf;
    }
  FATAL("buffer too small to read %s", name);
  return 0;
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
        fprintf(stderr, "\t+%d\t%s\n", usg->flag, usg->desc);
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
      pids	= alloc(pid_max);
    }
  if (pid>=pid_max)
    OOPS("process id %lu out of bounds, max is %u", pid, pid_max);
  else
    pids[pid] = 2;
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
print_event(int mask, const char *event, const struct fanotify_event_metadata *ptr, const char *name)
{
  000; /* XXX TODO XXX: escapes, ignores, etc.	*/
  printf("%s\t%ld\t%s\n", event, (long)ptr->pid, name);
}

static void
print_events(const struct fanotify_event_metadata *ptr)
{
  char		fdname[32], name[PATH_MAX];
  int		len, have;
  unsigned	bits;
  struct _modes *m;

  000;	/* XXX TODO XXX track PIDs	*/

  len	 = 0;

  if (ptr->fd>=0)
    {
      snprintf(fdname, sizeof fdname, "%d", ptr->fd);
      len	= readlink(fdname, name, (sizeof name)-1);
      if (len<0)
        {
          OOPS("cannot readlink %d", ptr->fd);
          len = 0;
        }
    }
  name[len] = 0;

  if (ptr->mask & PERMS_ALL)
    {
      struct fanotify_response r;
 
      if (flags & FLAG_VERBOSE)
        print_event(-1, "ALLOW", ptr, name);
      r.fd		= ptr->fd;
      r.response	= FAN_ALLOW;
      mywrite(fa, &r, sizeof r);
    }

  if (ptr->pid>0 && ptr->pid<pid_max && pids[ptr->pid]>1)
    return;	/* ignored by PID	*/

  have = 0;
  for (m=modes+1; m->name; m++)
    if ((bits=ptr->mask & (m->mode|m->perm))!=0)
      {
        print_event(bits, m->name, ptr, name);
        have = 1;
      }

  if (!have)
    print_event(MODES_ALL, "(UNKNOWN)", ptr, name);
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
          print_event(FAN_Q_OVERFLOW, "OVERFLOW", ptr, NULL);
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
