/* search.c - search devices based on a file or a filesystem label */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2005,2007,2008,2009  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/err.h>
#include <grub/dl.h>
#include <grub/device.h>
#include <grub/file.h>
#include <grub/env.h>
#include <grub/command.h>
#include <grub/search.h>
#include <grub/i18n.h>
#include <grub/disk.h>
#include <grub/partition.h>

GRUB_MOD_LICENSE ("GPLv3+");

void
FUNC_NAME (const char *key, const char *var, int no_floppy,
	   char **hints, unsigned nhints)
{
  int count = 0;
  grub_fs_autoload_hook_t saved_autoload;

  auto int iterate_device (const char *name);
  int iterate_device (const char *name)
  {
    int found = 0;

    /* Skip floppy drives when requested.  */
    if (no_floppy &&
	name[0] == 'f' && name[1] == 'd' && name[2] >= '0' && name[2] <= '9')
      return 0;

#ifdef DO_SEARCH_FILE
      {
	char *buf;
	grub_file_t file;

	buf = grub_xasprintf ("(%s)%s", name, key);
	if (! buf)
	  return 1;

	grub_file_filter_disable_compression ();
	file = grub_file_open (buf);
	if (file)
	  {
	    found = 1;
	    grub_file_close (file);
	  }
	grub_free (buf);
      }
#else
      {
	/* SEARCH_FS_UUID or SEARCH_LABEL */
	grub_device_t dev;
	grub_fs_t fs;
	char *quid;

	dev = grub_device_open (name);
	if (dev)
	  {
	    fs = grub_fs_probe (dev);

#ifdef DO_SEARCH_FS_UUID
#define compare_fn grub_strcasecmp
#define read_fn uuid
#else
#define compare_fn grub_strcmp
#define read_fn label
#endif

	    if (fs && fs->read_fn)
	      {
		fs->read_fn (dev, &quid);

		if (grub_errno == GRUB_ERR_NONE && quid)
		  {
		    if (compare_fn (quid, key) == 0)
		      found = 1;

		    grub_free (quid);
		  }
	      }

	    grub_device_close (dev);
	  }
      }
#endif

    if (found)
      {
	count++;
	if (var)
	  grub_env_set (var, name);
	else
	  grub_printf (" %s", name);
      }

    grub_errno = GRUB_ERR_NONE;
    return (found && var);
  }

  auto int part_hook (grub_disk_t disk, const grub_partition_t partition);
  int part_hook (grub_disk_t disk, const grub_partition_t partition)
  {
    char *partition_name, *devname;
    int ret;

    partition_name = grub_partition_get_name (partition);
    if (! partition_name)
      return 1;

    devname = grub_xasprintf ("%s,%s", disk->name, partition_name);
    grub_free (partition_name);
    if (!devname)
      return 1;
    ret = iterate_device (devname);
    grub_free (devname);    

    return ret;
  }

  auto void try (void);
  void try (void)    
  {
    unsigned i;
    for (i = 0; i < nhints; i++)
      {
	char *end;
	if (!hints[i][0])
	  continue;
	end = hints[i] + grub_strlen (hints[i]) - 1;
	if (*end == ',')
	  *end = 0;
	if (iterate_device (hints[i]))
	  {
	    if (!*end)
	      *end = ',';
	    return;
	  }
	if (!*end)
	  {
	    grub_device_t dev;
	    int ret;
	    dev = grub_device_open (hints[i]);
	    if (!dev)
	      {
		*end = ',';
		continue;
	      }
	    if (!dev->disk)
	      {
		grub_device_close (dev);
		*end = ',';
		continue;
	      }
	    ret = grub_partition_iterate (dev->disk, part_hook);
	    *end = ',';
	    grub_device_close (dev);
	    if (ret)
	      return;
	  }
      }
    grub_device_iterate (iterate_device);
  }

  /* First try without autoloading if we're setting variable. */
  if (var)
    {
      saved_autoload = grub_fs_autoload_hook;
      grub_fs_autoload_hook = 0;
      try ();

      /* Restore autoload hook.  */
      grub_fs_autoload_hook = saved_autoload;

      /* Retry with autoload if nothing found.  */
      if (grub_errno == GRUB_ERR_NONE && count == 0)
	try ();
    }
  else
    try ();

  if (grub_errno == GRUB_ERR_NONE && count == 0)
    grub_error (GRUB_ERR_FILE_NOT_FOUND, "no such device: %s", key);
}

static grub_err_t
grub_cmd_do_search (grub_command_t cmd __attribute__ ((unused)), int argc,
		    char **args)
{
  if (argc == 0)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "no argument specified");

  FUNC_NAME (args[0], argc == 1 ? 0 : args[1], 0, (args + 2),
	     argc > 2 ? argc - 2 : 0);

  return grub_errno;
}

static grub_command_t cmd;

#ifdef DO_SEARCH_FILE
GRUB_MOD_INIT(search_fs_file)
#elif defined (DO_SEARCH_FS_UUID)
GRUB_MOD_INIT(search_fs_uuid)
#else
GRUB_MOD_INIT(search_label)
#endif
{
  cmd =
    grub_register_command (COMMAND_NAME, grub_cmd_do_search,
			   N_("NAME [VARIABLE] [HINTS]"),
			   HELP_MESSAGE);
}

#ifdef DO_SEARCH_FILE
GRUB_MOD_FINI(search_fs_file)
#elif defined (DO_SEARCH_FS_UUID)
GRUB_MOD_FINI(search_fs_uuid)
#else
GRUB_MOD_FINI(search_label)
#endif
{
  grub_unregister_command (cmd);
}
