/* main.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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
#ifndef G10_MAIN_H
#define G10_MAIN_H
#include "types.h"
#include "iobuf.h"
#include "mpi.h"
#include "cipher.h"
#include "keydb.h"

#define DEFAULT_CIPHER_ALGO   CIPHER_ALGO_CAST5
#define DEFAULT_PUBKEY_ALGO   PUBKEY_ALGO_ELGAMAL
#define DEFAULT_DIGEST_ALGO   DIGEST_ALGO_SHA1
#define DEFAULT_COMPRESS_ALGO 1

typedef struct {
    int header_okay;
    PK_LIST pk_list;
    cipher_filter_context_t cfx;
} encrypt_filter_context_t;

struct groupitem
{
  char *name;
  STRLIST values;
  struct groupitem *next;
};

/*-- g10.c --*/
extern int g10_errors_seen;

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
  void g10_exit(int rc) __attribute__ ((noreturn));
#else
  void g10_exit(int rc);
#endif
void print_pubkey_algo_note( int algo );
void print_cipher_algo_note( int algo );
void print_digest_algo_note( int algo );

/*-- armor.c --*/
char *make_radix64_string( const byte *data, size_t len );

/*-- misc.c --*/
void trap_unaligned(void);
int disable_core_dumps(void);
u16 checksum_u16( unsigned n );
u16 checksum( byte *p, unsigned n );
u16 checksum_mpi( MPI a );
u32 buffer_to_u32( const byte *buffer );
const byte *get_session_marker( size_t *rlen );
int openpgp_cipher_test_algo( int algo );
int openpgp_pk_test_algo( int algo, unsigned int usage_flags );
int openpgp_pk_algo_usage ( int algo );
int openpgp_md_test_algo( int algo );
void idea_cipher_warn( int show );

struct expando_args
{
  PKT_public_key *pk;
  PKT_secret_key *sk;
  byte imagetype;
};

char *pct_expando(const char *string,struct expando_args *args);
int hextobyte( const char *s );
void deprecated_warning(const char *configname,unsigned int configlineno,
			const char *option,const char *repl1,const char *repl2);
const char *compress_algo_to_string(int algo);
int check_compress_algo(int algo);

/*-- helptext.c --*/
void display_online_help( const char *keyword );

/*-- encode.c --*/
int encode_symmetric( const char *filename );
int encode_store( const char *filename );
int encode_crypt( const char *filename, STRLIST remusr );
void encode_crypt_files(int nfiles, char **files, STRLIST remusr);
int encrypt_filter( void *opaque, int control,
		    IOBUF a, byte *buf, size_t *ret_len);


/*-- sign.c --*/
int complete_sig( PKT_signature *sig, PKT_secret_key *sk, MD_HANDLE md );
int sign_file( STRLIST filenames, int detached, STRLIST locusr,
	       int do_encrypt, STRLIST remusr, const char *outfile );
int clearsign_file( const char* input,size_t len, STRLIST locusr, char* output);
int sign_symencrypt_file (const char *fname, STRLIST locusr);
int write_one_signature (PKT_secret_key *sk, IOBUF out, MD_HANDLE hash,
                         int sigclass, u32 timestamp, u32 duration,
                         int status_letter);

/*-- sig-check.c --*/
int check_revocation_keys (PKT_public_key *pk, PKT_signature *sig);
int check_key_signature( KBNODE root, KBNODE node, int *is_selfsig );
int check_key_signature2( KBNODE root, KBNODE node,
			  int *is_selfsig, u32 *r_expiredate, int *r_expired );

/*-- delkey.c --*/
int delete_keys( STRLIST names, int secret, int allow_both );

/*-- keyedit.c --*/
void keyedit_menu( const char *username, STRLIST locusr, STRLIST cmds,
							    int sign_mode );
void show_basic_key_info (KBNODE keyblock);

/*-- keygen.c --*/
u32 ask_expire_interval(int object);
u32 ask_expiredate(void);
void generate_keypair( const char *fname );
int keygen_set_std_prefs (const char *string,int personal);
char *keygen_get_std_prefs (void);
int keygen_add_key_expire( PKT_signature *sig, void *opaque );
int keygen_add_std_prefs( PKT_signature *sig, void *opaque );
int keygen_upd_std_prefs( PKT_signature *sig, void *opaque );
int keygen_add_revkey(PKT_signature *sig, void *opaque);
int generate_subkeypair( KBNODE pub_keyblock, KBNODE sec_keyblock );

/*-- openfile.c --*/
int overwrite_filep( const char *fname );
char *make_outfile_name( const char *iname );
char *ask_outfile_name( const char *name, size_t namelen );
int   open_outfile( const char *iname, int mode, IOBUF *a );
IOBUF open_sigfile( const char *iname );
void try_make_homedir( const char *fname );

/*-- seskey.c --*/
void make_session_key( DEK *dek );
MPI encode_session_key( DEK *dek, unsigned nbits );
MPI encode_md_value( int pubkey_algo,  MD_HANDLE md,
		     int hash_algo, unsigned nbits, int v3compathack );

/*-- comment.c --*/
KBNODE make_comment_node( const char *s );
KBNODE make_mpi_comment_node( const char *s, MPI a );

/*-- import.c --*/
#define IMPORT_ALLOW_LOCAL_SIGS      1
#define IMPORT_REPAIR_HKP_SUBKEY_BUG 2

int parse_import_options(char *str,unsigned int *options);
void import_keys( char **fnames, int nnames, int fast,
		  void *stats_hd, unsigned int options );
int import_keys_stream( IOBUF inp, int fast,
			void *stats_hd, unsigned int options );
void *import_new_stats_handle (void);
void import_release_stats_handle (void *p);
void import_print_stats (void *hd);

int collapse_uids( KBNODE *keyblock );

/*-- export.c --*/
#define EXPORT_INCLUDE_NON_RFC           1
#define EXPORT_INCLUDE_LOCAL_SIGS        2
#define EXPORT_INCLUDE_ATTRIBUTES        4
#define EXPORT_INCLUDE_SENSITIVE_REVKEYS 8

int parse_export_options(char *str,unsigned int *options);
int export_pubkeys( STRLIST users, unsigned int options );
int export_pubkeys_stream( IOBUF out, STRLIST users, unsigned int options );
int export_seckeys( STRLIST users );
int export_secsubkeys( STRLIST users );

/* dearmor.c --*/
int dearmor_file( const char *fname );
int enarmor_file( const char *fname );

/*-- revoke.c --*/
struct revocation_reason_info;
int gen_revoke( const char *uname );
int gen_desig_revoke( const char *uname );
int revocation_reason_build_cb( PKT_signature *sig, void *opaque );
struct revocation_reason_info *
		ask_revocation_reason( int key_rev, int cert_rev, int hint );
void release_revocation_reason_info( struct revocation_reason_info *reason );

/*-- keylist.c --*/
void public_key_list( STRLIST list );
void secret_key_list( STRLIST list );
void list_keyblock( KBNODE keyblock, int secret, int fpr, void *opaque );
void print_fingerprint (PKT_public_key *pk, PKT_secret_key *sk, int mode);
void show_policy_url(PKT_signature *sig,int indent);
void show_notation(PKT_signature *sig,int indent);
void set_attrib_fd(int fd);

/*-- verify.c --*/
void print_file_status( int status, const char *name, int what );
int verify_signatures( int nfiles, char **files );
int verify_files( int nfiles, char **files );
int verify_one_file( const char *name );

/*-- decrypt.c --*/
int decrypt_message( const char *filename );
void decrypt_messages(int nfiles, char **files);

/*-- plaintext.c --*/
int hash_datafiles( MD_HANDLE md, MD_HANDLE md2,
		    STRLIST files, const char *sigfilename, int textmode );

/*-- pipemode.c --*/
void run_in_pipemode (void);

/*-- signal.c --*/
void init_signals(void);
void pause_on_sigusr( int which );
void block_all_signals(void);
void unblock_all_signals(void);

#endif /*G10_MAIN_H*/
