/* photoid.c - photo ID handling code
 * Copyright (C) 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifdef __MINGW32__ 
# include <windows.h>
# ifndef VER_PLATFORM_WIN32_WINDOWS
#  define VER_PLATFORM_WIN32_WINDOWS 1
# endif
#endif
#include "packet.h"
#include "status.h"
#include "exec.h"
#include "keydb.h"
#include "util.h"
#include "i18n.h"
#include "iobuf.h"
#include "memory.h"
#include "options.h"
#include "main.h"
#include "photoid.h"

/* Generate a new photo id packet, or return NULL if canceled */
PKT_user_id *generate_photo_id(PKT_public_key *pk)
{
  PKT_user_id *uid;
  int error=1,i;
  unsigned int len;
  char *filename=NULL;
  byte *photo=NULL;
  byte header[16];
  IOBUF file;

  header[0]=0x10; /* little side of photo header length */
  header[1]=0;    /* big side of photo header length */
  header[2]=1;    /* 1 == version of photo header */
  header[3]=1;    /* 1 == JPEG */

  for(i=4;i<16;i++) /* The reserved bytes */
    header[i]=0;

#define EXTRA_UID_NAME_SPACE 71
  uid=m_alloc_clear(sizeof(*uid)+71);

  printf(_("\nPick an image to use for your photo ID.  "
	   "The image must be a JPEG file.\n"
	   "Remember that the image is stored within your public key.  "
	   "If you use a\n"
	   "very large picture, your key will become very large as well!\n"
	   "Keeping the image close to 240x288 is a good size to use.\n"));

  while(photo==NULL)
    {
      printf("\n");

      m_free(filename);

      filename=cpr_get("photoid.jpeg.add",
		       _("Enter JPEG filename for photo ID: "));

      if(strlen(filename)==0)
	goto scram;

      file=iobuf_open(filename);
      if(!file)
	{
	  log_error(_("Unable to open photo \"%s\": %s\n"),
		    filename,strerror(errno));
	  continue;
	}

      len=iobuf_get_filelength(file);
      if(len>6144)
	{
	  printf("This JPEG is really large (%d bytes) !\n",len);
	  if(!cpr_get_answer_is_yes("photoid.jpeg.size",
			    _("Are you sure you want to use it (y/N)? ")))
	  {
	    iobuf_close(file);
	    continue;
	  }
	}

      photo=m_alloc(len);
      iobuf_read(file,photo,len);
      iobuf_close(file);

      /* Is it a JPEG? */
      if(photo[0]!=0xFF || photo[1]!=0xD8 ||
	 photo[6]!='J' || photo[7]!='F' || photo[8]!='I' || photo[9]!='F')
	{
	  log_error(_("\"%s\" is not a JPEG file\n"),filename);
	  m_free(photo);
	  photo=NULL;
	  continue;
	}

      /* Build the packet */
      build_attribute_subpkt(uid,1,photo,len,header,16);
      parse_attribute_subpkts(uid);
      make_attribute_uidname(uid, EXTRA_UID_NAME_SPACE);

      /* Showing the photo is not safe when noninteractive since the
         "user" may not be able to dismiss a viewer window! */
      if(opt.command_fd==-1)
	{
	  show_photos(uid->attribs,uid->numattribs,pk,NULL);
	  switch(cpr_get_answer_yes_no_quit("photoid.jpeg.okay",
					 _("Is this photo correct (y/N/q)? ")))
	    {
	    case -1:
	      goto scram;
	    case 0:
	      free_attributes(uid);
	      m_free(photo);
	      photo=NULL;
	      continue;
	    }
	}
    }

  error=0;
  uid->ref=1;

 scram:
  m_free(filename);
  m_free(photo);

  if(error)
    {
      free_attributes(uid);
      m_free(uid);
      return NULL;
    }

  return uid;
}

/* Returns 0 for error, 1 for valid */
int parse_image_header(const struct user_attribute *attr,byte *type,u32 *len)
{
  u16 headerlen;

  if(attr->len<3)
    return 0;

  /* For historical reasons (i.e. "oops!"), the header length is
     little endian. */
  headerlen=(attr->data[1]<<8) | attr->data[0];

  if(headerlen>attr->len)
    return 0;

  if(type && attr->len>=4)
    {
      if(attr->data[2]==1) /* header version 1 */
	*type=attr->data[3];
      else
	*type=0;
    }

  *len=attr->len-headerlen;

  if(*len==0)
    return 0;

  return 1;
}

/* style==0 for extension, 1 for name, 2 for MIME type.  Remember that
   the "name" style string could be used in a user ID name field, so
   make sure it is not too big (see
   parse-packet.c:parse_attribute). */
char *image_type_to_string(byte type,int style)
{
  char *string;

  switch(type)
    {
    case 1: /* jpeg */
      if(style==0)
	string="jpg";
      else if(style==1)
	string="jpeg";
      else
	string="image/jpeg";
      break;

    default:
      if(style==0)
	string="bin";
      else if(style==1)
	string="unknown";
      else
	string="image/x-unknown";
      break;
    }

  return string;
}

#if !defined(FIXED_PHOTO_VIEWER) && !defined(DISABLE_PHOTO_VIEWER)
static const char *get_default_photo_command(void)
{
#if defined(__MINGW32__)
  OSVERSIONINFO osvi;

  memset(&osvi,0,sizeof(osvi));
  osvi.dwOSVersionInfoSize=sizeof(osvi);
  GetVersionEx(&osvi);

  if(osvi.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS)
    return "start /w %i";
  else
    return "cmd /c start /w %i";
#elif defined(__APPLE__)
  /* OS X.  This really needs more than just __APPLE__. */
  return "open %I";
#elif defined(__riscos__)
  return "Filer_Run %I";
#else
  return "xloadimage -fork -quiet -title 'KeyID 0x%k' stdin";
#endif
}
#endif

void show_photos(const struct user_attribute *attrs,
		 int count,PKT_public_key *pk,PKT_secret_key *sk)
{
#ifndef DISABLE_PHOTO_VIEWER
  int i;
  struct expando_args args;
  u32 len;
  u32 kid[2]={0,0};

  memset(&args,0,sizeof(args));
  args.pk=pk;
  args.sk=sk;

  if(pk)
    keyid_from_pk(pk,kid);
  else if(sk)
    keyid_from_sk(sk,kid);

  for(i=0;i<count;i++)
    if(attrs[i].type==ATTRIB_IMAGE &&
       parse_image_header(&attrs[i],&args.imagetype,&len))
      {
	char *command,*name;
	struct exec_info *spawn;
	int offset=attrs[i].len-len;

#ifdef FIXED_PHOTO_VIEWER
	opt.photo_viewer=FIXED_PHOTO_VIEWER;
#else
	if(!opt.photo_viewer)
	  opt.photo_viewer=get_default_photo_command();
#endif

	/* make command grow */
	command=pct_expando(opt.photo_viewer,&args);
	if(!command)
	  goto fail;

	name=m_alloc(16+strlen(EXTSEP_S)+
		     strlen(image_type_to_string(args.imagetype,0))+1);

	/* Make the filename.  Notice we are not using the image
           encoding type for more than cosmetics.  Most external image
           viewers can handle a multitude of types, and even if one
           cannot understand a partcular type, we have no way to know
           which.  The spec permits this, by the way. -dms */

#ifdef USE_ONLY_8DOT3
	sprintf(name,"%08lX" EXTSEP_S "%s",(ulong)kid[1],
		image_type_to_string(args.imagetype,0));
#else
	sprintf(name,"%08lX%08lX" EXTSEP_S "%s",(ulong)kid[0],(ulong)kid[1],
		image_type_to_string(args.imagetype,0));
#endif

	if(exec_write(&spawn,NULL,command,name,1,1)!=0)
	  {
	    m_free(name);
	    goto fail;
	  }

#ifdef __riscos__
        riscos_set_filetype(spawn->tempfile_in,
                            image_type_to_string(args.imagetype,2));
#endif

	m_free(name);

	fwrite(&attrs[i].data[offset],attrs[i].len-offset,1,spawn->tochild);

	if(exec_read(spawn)!=0)
	  {
	    exec_finish(spawn);
	    goto fail;
	  }

	if(exec_finish(spawn)!=0)
	  goto fail;
      }

  return;

 fail:
  log_error("unable to display photo ID!\n");
#endif
}
