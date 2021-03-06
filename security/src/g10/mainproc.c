/* mainproc.c - handle packets
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "packet.h"
#include "iobuf.h"
#include "memory.h"
#include "options.h"
#include "util.h"
#include "cipher.h"
#include "keydb.h"
#include "filter.h"
#include "main.h"
#include "status.h"
#include "i18n.h"
#include "trustdb.h"
#include "keyserver-internal.h"
#include "photoid.h"


struct kidlist_item {
    struct kidlist_item *next;
    u32 kid[2];
    int pubkey_algo;
    int reason;
};



/****************
 * Structure to hold the context
 */
typedef struct mainproc_context *CTX;
struct mainproc_context {
    struct mainproc_context *anchor;  /* may be useful in the future */
    PKT_public_key *last_pubkey;
    PKT_secret_key *last_seckey;
    PKT_user_id     *last_user_id;
    md_filter_context_t mfx;
    int sigs_only;   /* process only signatures and reject all other stuff */
    int encrypt_only; /* process only encrytion messages */
    STRLIST signed_data;
    const char *sigfilename;
    DEK *dek;
    int last_was_session_key;
    KBNODE list;   /* the current list of packets */
    int have_data;
    IOBUF iobuf;    /* used to get the filename etc. */
    int trustletter; /* temp usage in list_node */
    ulong local_id;    /* ditto */
    struct kidlist_item *pkenc_list;	/* list of encryption packets */
    struct {
        int op;
        int stop_now;
    } pipemode;
};


static int do_proc_packets( CTX c, IOBUF a);

static void list_node( CTX c, KBNODE node );
static int proc_tree( CTX c, KBNODE node );


static int
release_list( CTX c )
{
    int rc;

    if( !c->list )
	return;
    rc = proc_tree(c, c->list );
    release_kbnode( c->list );
    while( c->pkenc_list ) {
	struct kidlist_item *tmp = c->pkenc_list->next;
	m_free( c->pkenc_list );
	c->pkenc_list = tmp;
    }
    c->pkenc_list = NULL;
    c->list = NULL;
    c->have_data = 0;
    c->last_was_session_key = 0;
    c->pipemode.op = 0;
    c->pipemode.stop_now = 0;
    m_free(c->dek); c->dek = NULL;
    return rc;
}


static int
add_onepass_sig( CTX c, PACKET *pkt )
{
    KBNODE node;

    if( c->list ) { /* add another packet */
        /* We can only append another onepass packet if the list
         * does contain only onepass packets */
        for( node=c->list; node && node->pkt->pkttype == PKT_ONEPASS_SIG;
             node = node->next )
            ;
	if( node ) {
            /* this is not the case, so we flush the current thing and 
             * allow this packet to start a new verification thing */
	   release_list( c );
	   c->list = new_kbnode( pkt );
	}
	else
	   add_kbnode( c->list, new_kbnode( pkt ));
    }
    else /* insert the first one */
	c->list = node = new_kbnode( pkt );

    return 1;
}


static int
add_gpg_control( CTX c, PACKET *pkt )
{
    if ( pkt->pkt.gpg_control->control == CTRLPKT_CLEARSIGN_START ) {
        /* New clear text signature.
         * Process the last one and reset everything */
        release_list(c);
    }   
    else if ( pkt->pkt.gpg_control->control == CTRLPKT_PIPEMODE ) {
        /* Pipemode control packet */
        if ( pkt->pkt.gpg_control->datalen < 2 ) 
            log_fatal ("invalid pipemode control packet length\n");
        if (pkt->pkt.gpg_control->data[0] == 1) {
            /* start the whole thing */
            assert ( !c->list ); /* we should be in a pretty virgin state */
            assert ( !c->pipemode.op );
            c->pipemode.op = pkt->pkt.gpg_control->data[1];
        }
        else if (pkt->pkt.gpg_control->data[0] == 2) {
            /* the signed material follows in a plaintext packet */
            assert ( c->pipemode.op == 'B' );
        }
        else if (pkt->pkt.gpg_control->data[0] == 3) {
            assert ( c->pipemode.op == 'B' );
            release_list (c);
            /* and tell the outer loop to terminate */
            c->pipemode.stop_now = 1;
        }
        else 
            log_fatal ("invalid pipemode control packet code\n");
        return 0; /* no need to store the packet */
    }   

    if( c->list )  /* add another packet */
        add_kbnode( c->list, new_kbnode( pkt ));
    else /* insert the first one */
	c->list = new_kbnode( pkt );

    return 1;
}



static int
add_user_id( CTX c, PACKET *pkt )
{
    if( !c->list ) {
	log_error("orphaned user ID\n" );
	return 0;
    }
    add_kbnode( c->list, new_kbnode( pkt ) );
    return 1;
}

static int
add_subkey( CTX c, PACKET *pkt )
{
    if( !c->list ) {
	log_error("subkey w/o mainkey\n" );
	return 0;
    }
    add_kbnode( c->list, new_kbnode( pkt ) );
    return 1;
}

static int
add_ring_trust( CTX c, PACKET *pkt )
{
    if( !c->list ) {
	log_error("ring trust w/o key\n" );
	return 0;
    }
    add_kbnode( c->list, new_kbnode( pkt ) );
    return 1;
}


static int
add_signature( CTX c, PACKET *pkt )
{
    KBNODE node;

    if( pkt->pkttype == PKT_SIGNATURE && !c->list ) {
	/* This is the first signature for the following datafile.
	 * GPG does not write such packets; instead it always uses
	 * onepass-sig packets.  The drawback of PGP's method
	 * of prepending the signature to the data is
	 * that it is not possible to make a signature from data read
	 * from stdin.	(GPG is able to read PGP stuff anyway.) */
	node = new_kbnode( pkt );
	c->list = node;
	return 1;
    }
    else if( !c->list )
	return 0; /* oops (invalid packet sequence)*/
    else if( !c->list->pkt )
	BUG();	/* so nicht */

    /* add a new signature node id at the end */
    node = new_kbnode( pkt );
    add_kbnode( c->list, node );
    return 1;
}

static void
symkey_decrypt_sesskey( DEK *dek, byte *sesskey, size_t slen )
{
    CIPHER_HANDLE hd;
    int n;

    if ( slen < 17 || slen > 33 ) {
        log_error ( _("weird size for an encrypted session key (%d)\n"),
		    (int)slen);
        return;   
    }
    hd = cipher_open( dek->algo, CIPHER_MODE_CFB, 1 );
    cipher_setkey( hd, dek->key, dek->keylen );
    cipher_setiv( hd, NULL, 0 );
    cipher_decrypt( hd, sesskey, sesskey, slen );
    cipher_close( hd );
    /* check first byte (the cipher algo) */
    if ( sesskey[0] > 10 ) {
        log_error ( _("invalid symkey algorithm detected (%d)\n"),
                    sesskey[0] );
        return;
    }
    n = cipher_get_keylen (sesskey[0]) / 8;
    if (n > DIM(dek->key))
         BUG ();
    /* now we replace the dek components with the real session key
       to decrypt the contents of the sequencing packet. */
    dek->keylen = cipher_get_keylen( sesskey[0] ) / 8;
    dek->algo = sesskey[0];
    memcpy( dek->key, sesskey + 1, dek->keylen );
    /*log_hexdump( "thekey", dek->key, dek->keylen );*/
}   

static void
proc_symkey_enc( CTX c, PACKET *pkt )
{
    PKT_symkey_enc *enc;

    enc = pkt->pkt.symkey_enc;
    if (!enc)
        log_error ("invalid symkey encrypted packet\n");
    else {
        int algo = enc->cipher_algo;
	const char *s;

	s = cipher_algo_to_string (algo);
	if( s )
	    log_info(_("%s encrypted data\n"), s );
	else
	    log_info(_("encrypted with unknown algorithm %d\n"), algo );

	c->last_was_session_key = 2;
	if ( opt.list_only )
    	    goto leave;
	c->dek = passphrase_to_dek( NULL, 0, algo, &enc->s2k, 0, NULL );
        if (c->dek)
            c->dek->algo_info_printed = 1;
        if ( c->dek && enc->seskeylen )
            symkey_decrypt_sesskey( c->dek, enc->seskey, enc->seskeylen );
    }
leave:
    free_packet(pkt);
}

static void
proc_pubkey_enc( CTX c, PACKET *pkt )
{
    PKT_pubkey_enc *enc;
    int result = 0;

    /* check whether the secret key is available and store in this case */
    c->last_was_session_key = 1;
    enc = pkt->pkt.pubkey_enc;
    /*printf("enc: encrypted by a pubkey with keyid %08lX\n", enc->keyid[1] );*/
    /* Hmmm: why do I have this algo check here - anyway there is
     * function to check it. */
    if( opt.verbose )
	log_info(_("public key is %08lX\n"), (ulong)enc->keyid[1] );

    if( is_status_enabled() ) {
	char buf[50];
	sprintf(buf, "%08lX%08lX %d 0",
		(ulong)enc->keyid[0], (ulong)enc->keyid[1], enc->pubkey_algo );
	write_status_text( STATUS_ENC_TO, buf );
    }

    if( !opt.list_only && opt.override_session_key ) {
	/* It does not make much sense to store the session key in
	 * secure memory because it has already been passed on the
	 * command line and the GCHQ knows about it */
	c->dek = m_alloc_clear( sizeof *c->dek );
	result = get_override_session_key ( c->dek, opt.override_session_key );
	if ( result ) {
	    m_free(c->dek); c->dek = NULL;
	}
    }
    else if( is_ELGAMAL(enc->pubkey_algo)
	|| enc->pubkey_algo == PUBKEY_ALGO_DSA
	|| is_RSA(enc->pubkey_algo)  ) {
	if ( !c->dek && ((!enc->keyid[0] && !enc->keyid[1])
                          || opt.try_all_secrets
			  || !seckey_available( enc->keyid )) ) {
	    if( opt.list_only )
		result = -1;
	    else {
		c->dek = m_alloc_secure_clear( sizeof *c->dek );
		if( (result = get_session_key( enc, c->dek )) ) {
		    /* error: delete the DEK */
		    m_free(c->dek); c->dek = NULL;
		}
	    }
	}
	else
	    result = G10ERR_NO_SECKEY;
    }
    else
	result = G10ERR_PUBKEY_ALGO;

    if( result == -1 )
	;
    else {
        if( !result ) {
            if( opt.verbose > 1 )
                log_info( _("public key encrypted data: good DEK\n") );
            if ( opt.show_session_key ) {
                int i;
                char *buf = m_alloc ( c->dek->keylen*2 + 20 );
                sprintf ( buf, "%d:", c->dek->algo );
                for(i=0; i < c->dek->keylen; i++ )
                    sprintf(buf+strlen(buf), "%02X", c->dek->key[i] );
                log_info( "session key: \"%s\"\n", buf );
                write_status_text ( STATUS_SESSION_KEY, buf );
            }
        }
        /* store it for later display */
        {
            struct kidlist_item *x = m_alloc( sizeof *x );
            x->kid[0] = enc->keyid[0];
            x->kid[1] = enc->keyid[1];
            x->pubkey_algo = enc->pubkey_algo;
            x->reason = result;
            x->next = c->pkenc_list;
            c->pkenc_list = x;
        }
    }
    free_packet(pkt);
}



/****************
 * Print the list of public key encrypted packets which we could
 * not decrypt.
 */
static void
print_pkenc_list( struct kidlist_item *list, int failed )
{
    for( ; list; list = list->next ) {
	PKT_public_key *pk;
	const char *algstr;
        
        if ( failed && !list->reason )
            continue;
        if ( !failed && list->reason )
            continue;

        algstr = pubkey_algo_to_string( list->pubkey_algo );
        pk = m_alloc_clear( sizeof *pk );

	if( !algstr )
	    algstr = "[?]";
	pk->pubkey_algo = list->pubkey_algo;
	if( !get_pubkey( pk, list->kid ) ) {
	    size_t n;
	    char *p;
	    log_info( _("encrypted with %u-bit %s key, ID %08lX, created %s\n"),
		       nbits_from_pk( pk ), algstr, (ulong)list->kid[1],
		       strtimestamp(pk->timestamp) );
	    fputs("      \"", log_stream() );
	    p = get_user_id( list->kid, &n );
	    print_utf8_string2 ( log_stream(), p, n, '"' );
	    m_free(p);
	    fputs("\"\n", log_stream() );
	}
	else {
	    log_info(_("encrypted with %s key, ID %08lX\n"),
			algstr, (ulong) list->kid[1] );
	}
	free_public_key( pk );

	if( list->reason == G10ERR_NO_SECKEY ) {
	    if( is_status_enabled() ) {
		char buf[20];
		sprintf(buf,"%08lX%08lX", (ulong)list->kid[0],
					  (ulong)list->kid[1] );
		write_status_text( STATUS_NO_SECKEY, buf );
	    }
	}
	else if (list->reason)
	    log_info(_("public key decryption failed: %s\n"),
						g10_errstr(list->reason));
    }
}


static void
proc_encrypted( CTX c, PACKET *pkt )
{
    int result = 0;

    if (!opt.quiet) {
        print_pkenc_list ( c->pkenc_list, 1 );
        print_pkenc_list ( c->pkenc_list, 0 );
    }

    write_status( STATUS_BEGIN_DECRYPTION );

    /*log_debug("dat: %sencrypted data\n", c->dek?"":"conventional ");*/
    if( opt.list_only )
	result = -1;
    else if( !c->dek && !c->last_was_session_key ) {
        int algo;
        STRING2KEY s2kbuf, *s2k = NULL;

	/* assume this is old style conventional encrypted data */
        if ( (algo = opt.def_cipher_algo))
            log_info (_("assuming %s encrypted data\n"),
                        cipher_algo_to_string(algo));
        else if ( check_cipher_algo(CIPHER_ALGO_IDEA) ) {
            algo = opt.def_cipher_algo;
            if (!algo)
                algo = opt.s2k_cipher_algo;
	    idea_cipher_warn(1);
            log_info (_("IDEA cipher unavailable, "
                        "optimistically attempting to use %s instead\n"),
                       cipher_algo_to_string(algo));
        }
        else {
            algo = CIPHER_ALGO_IDEA;
            if (!opt.def_digest_algo) {
                /* If no digest is given we assume MD5 */
                s2kbuf.mode = 0;
                s2kbuf.hash_algo = DIGEST_ALGO_MD5;
                s2k = &s2kbuf;
            }
            log_info (_("assuming %s encrypted data\n"), "IDEA");
        }

	c->dek = passphrase_to_dek ( NULL, 0, algo, s2k, 0, NULL );
        if (c->dek)
            c->dek->algo_info_printed = 1;
    }
    else if( !c->dek )
	result = G10ERR_NO_SECKEY;
    if( !result )
	result = decrypt_data( c, pkt->pkt.encrypted, c->dek );

    m_free(c->dek); c->dek = NULL;
    if( result == -1 )
	;
    else if( !result || (result==G10ERR_BAD_SIGN && opt.ignore_mdc_error)) {
	write_status( STATUS_DECRYPTION_OKAY );
	if( opt.verbose > 1 )
	    log_info(_("decryption okay\n"));
	if( pkt->pkt.encrypted->mdc_method && !result )
	    write_status( STATUS_GOODMDC );
	else if(!opt.no_mdc_warn)
	    log_info ("WARNING: message was not integrity protected\n");
    }
    else if( result == G10ERR_BAD_SIGN ) {
	log_error(_("WARNING: encrypted message has been manipulated!\n"));
	write_status( STATUS_BADMDC );
	write_status( STATUS_DECRYPTION_FAILED );
    }
    else {
	write_status( STATUS_DECRYPTION_FAILED );
	log_error(_("decryption failed: %s\n"), g10_errstr(result));
	/* Hmmm: does this work when we have encrypted using multiple
	 * ways to specify the session key (symmmetric and PK)*/
    }
    free_packet(pkt);
    c->last_was_session_key = 0;
    write_status( STATUS_END_DECRYPTION );
}



static void
proc_plaintext( CTX c, PACKET *pkt, IOBUF buff)
{
    PKT_plaintext *pt = pkt->pkt.plaintext;
    int any, clearsig, only_md5, rc;
    KBNODE n;

    if( pt->namelen == 8 && !memcmp( pt->name, "_CONSOLE", 8 ) )
	log_info(_("NOTE: sender requested \"for-your-eyes-only\"\n"));
    else if( opt.verbose )
	log_info(_("original file name='%.*s'\n"), pt->namelen, pt->name);
    free_md_filter_context( &c->mfx );
    c->mfx.md = md_open( 0, 0);
    /* fixme: we may need to push the textfilter if we have sigclass 1
     * and no armoring - Not yet tested
     * Hmmm, why don't we need it at all if we have sigclass 1
     * Should we assume that plaintext in mode 't' has always sigclass 1??
     * See: Russ Allbery's mail 1999-02-09
     */
    any = clearsig = only_md5 = 0;
    for(n=c->list; n; n = n->next ) {
	if( n->pkt->pkttype == PKT_ONEPASS_SIG ) {
	    if( n->pkt->pkt.onepass_sig->digest_algo ) {
		md_enable( c->mfx.md, n->pkt->pkt.onepass_sig->digest_algo );
		if( !any && n->pkt->pkt.onepass_sig->digest_algo
						      == DIGEST_ALGO_MD5 )
		    only_md5 = 1;
		else
		    only_md5 = 0;
		any = 1;
	    }
	    if( n->pkt->pkt.onepass_sig->sig_class != 0x01 )
		only_md5 = 0;
	}
	else if( n->pkt->pkttype == PKT_GPG_CONTROL
                 && n->pkt->pkt.gpg_control->control
                    == CTRLPKT_CLEARSIGN_START ) {
            size_t datalen = n->pkt->pkt.gpg_control->datalen;
            const byte *data = n->pkt->pkt.gpg_control->data;

            /* check that we have at least the sigclass and one hash */
            if ( datalen < 2 )
                log_fatal("invalid control packet CTRLPKT_CLEARSIGN_START\n"); 
            /* Note that we don't set the clearsig flag for not-dash-escaped
             * documents */
            clearsig = (*data == 0x01);
            for( data++, datalen--; datalen; datalen--, data++ )
                md_enable( c->mfx.md, *data );
            any = 1;
            break;  /* no pass signature pakets are expected */
        }
    }

    if( !any && !opt.skip_verify ) {
	/* no onepass sig packet: enable all standard algos */
	md_enable( c->mfx.md, DIGEST_ALGO_RMD160 );
	md_enable( c->mfx.md, DIGEST_ALGO_SHA1 );
	md_enable( c->mfx.md, DIGEST_ALGO_MD5 );
    }
    if( opt.pgp2_workarounds && only_md5 && !opt.skip_verify ) {
	/* This is a kludge to work around a bug in pgp2.  It does only
	 * catch those mails which are armored.  To catch the non-armored
	 * pgp mails we could see whether there is the signature packet
	 * in front of the plaintext.  If someone needs this, send me a patch.
	 */
	c->mfx.md2 = md_open( DIGEST_ALGO_MD5, 0);
    }
    if ( DBG_HASHING ) {
	md_start_debug( c->mfx.md, "verify" );
	if ( c->mfx.md2  )
	    md_start_debug( c->mfx.md2, "verify2" );
    }
    if ( c->pipemode.op == 'B' )
        rc = handle_plaintext( pt, &c->mfx, 1, 0, buff);
    else {
        rc = handle_plaintext( pt, &c->mfx, c->sigs_only, clearsig, buff);
        if( rc == G10ERR_CREATE_FILE && !c->sigs_only) {
            /* can't write output but we hash it anyway to
             * check the signature */
            rc = handle_plaintext( pt, &c->mfx, 1, clearsig, buff);
        }
    }
    if( rc )
	log_error( "handle plaintext failed: %s\n", g10_errstr(rc));
    free_packet(pkt);
    c->last_was_session_key = 0;

    /* We add a marker control packet instead of the plaintext packet.
     * This is so that we can later detect invalid packet sequences.
     */
    n = new_kbnode (create_gpg_control (CTRLPKT_PLAINTEXT_MARK, NULL, 0));
    if (c->list)
        add_kbnode (c->list, n);
    else 
        c->list = n;
}


static int
proc_compressed_cb( IOBUF a, void *info )
{
    return proc_signature_packets( info, a, ((CTX)info)->signed_data,
					    ((CTX)info)->sigfilename );
}

static int
proc_encrypt_cb( IOBUF a, void *info )
{
    return proc_encryption_packets( info, a );
}

static void
proc_compressed( CTX c, PACKET *pkt )
{
    PKT_compressed *zd = pkt->pkt.compressed;
    int rc;

    /*printf("zip: compressed data packet\n");*/
    if( c->sigs_only )
	rc = handle_compressed( c, zd, proc_compressed_cb, c );
    else if( c->encrypt_only )
	rc = handle_compressed( c, zd, proc_encrypt_cb, c );
    else
	rc = handle_compressed( c, zd, NULL, NULL );
    if( rc )
	log_error("uncompressing failed: %s\n", g10_errstr(rc));
    free_packet(pkt);
    c->last_was_session_key = 0;
}

/****************
 * check the signature
 * Returns: 0 = valid signature or an error code
 */
static int
do_check_sig( CTX c, KBNODE node, int *is_selfsig, int *is_expkey )
{
    PKT_signature *sig;
    MD_HANDLE md = NULL, md2 = NULL;
    int algo, rc, dum2;
    u32 dummy;

    if(!is_expkey)
      is_expkey=&dum2;

    assert( node->pkt->pkttype == PKT_SIGNATURE );
    if( is_selfsig )
	*is_selfsig = 0;
    sig = node->pkt->pkt.signature;

    algo = sig->digest_algo;
    if( (rc=check_digest_algo(algo)) )
	return rc;

    if( sig->sig_class == 0x00 ) {
	if( c->mfx.md )
	    md = md_copy( c->mfx.md );
	else /* detached signature */
	    md = md_open( 0, 0 ); /* signature_check() will enable the md*/
    }
    else if( sig->sig_class == 0x01 ) {
	/* how do we know that we have to hash the (already hashed) text
	 * in canonical mode ??? (calculating both modes???) */
	if( c->mfx.md ) {
	    md = md_copy( c->mfx.md );
	    if( c->mfx.md2 )
	       md2 = md_copy( c->mfx.md2 );
	}
	else { /* detached signature */
	  log_debug("Do we really need this here?");
	    md = md_open( 0, 0 ); /* signature_check() will enable the md*/
	    md2 = md_open( 0, 0 );
	}
    }
    else if( (sig->sig_class&~3) == 0x10
	     || sig->sig_class == 0x18
             || sig->sig_class == 0x1f
	     || sig->sig_class == 0x20
	     || sig->sig_class == 0x28
	     || sig->sig_class == 0x30	) { 
	if( c->list->pkt->pkttype == PKT_PUBLIC_KEY
	    || c->list->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	    return check_key_signature( c->list, node, is_selfsig );
	}
	else if( sig->sig_class == 0x20 ) {
	    log_info(_("standalone revocation - "
		       "use \"gpg --import\" to apply\n"));
	    return G10ERR_NOT_PROCESSED;
	}
	else {
	    log_error("invalid root packet for sigclass %02x\n",
							sig->sig_class);
	    return G10ERR_SIG_CLASS;
	}
    }
    else
	return G10ERR_SIG_CLASS;
    rc = signature_check2( sig, md, &dummy, is_expkey );
    if( rc == G10ERR_BAD_SIGN && md2 )
	rc = signature_check2( sig, md2, &dummy, is_expkey );
    md_close(md);
    md_close(md2);

    return rc;
}


static void
print_userid( PACKET *pkt )
{
    if( !pkt )
	BUG();
    if( pkt->pkttype != PKT_USER_ID ) {
	printf("ERROR: unexpected packet type %d", pkt->pkttype );
	return;
    }
    if( opt.with_colons )
      {
	if(pkt->pkt.user_id->attrib_data)
	  printf("%u %lu",
		 pkt->pkt.user_id->numattribs,
		 pkt->pkt.user_id->attrib_len);
	else
	  print_string( stdout,  pkt->pkt.user_id->name,
			pkt->pkt.user_id->len, ':');
      }
    else
	print_utf8_string( stdout,  pkt->pkt.user_id->name,
				     pkt->pkt.user_id->len );
}


static void
print_notation_data( PKT_signature *sig )
{
    size_t n, n1, n2;
    const byte *p;
    int seq = 0;

    while((p=enum_sig_subpkt(sig->hashed,SIGSUBPKT_NOTATION,&n,&seq,NULL))) {
	if( n < 8 ) {
	    log_info(_("WARNING: invalid notation data found\n"));
	    return;
	}
	if( !(*p & 0x80) )
	    return; /* not human readable */
	n1 = (p[4] << 8) | p[5];
	n2 = (p[6] << 8) | p[7];
	p += 8;
	if( 8+n1+n2 != n ) {
	    log_info(_("WARNING: invalid notation data found\n"));
	    return;
	}
	log_info(_("Notation: ") );
	print_string( log_stream(), p, n1, 0 );
	putc( '=', log_stream() );
	print_string( log_stream(), p+n1, n2, 0 );
	putc( '\n', log_stream() );
        write_status_buffer ( STATUS_NOTATION_NAME, p   , n1, 0 );
        write_status_buffer ( STATUS_NOTATION_DATA, p+n1, n2, 50 );
    }

    seq=0;

    while((p=enum_sig_subpkt(sig->hashed,SIGSUBPKT_POLICY,&n,&seq,NULL))) {
	log_info(_("Policy: ") );
	print_string( log_stream(), p, n, 0 );
	putc( '\n', log_stream() );
        write_status_buffer ( STATUS_POLICY_URL, p, n, 0 );
    }

    /* Now check whether the key of this signature has some
     * notation data */

    /* TODO */
}


/****************
 * List the certificate in a user friendly way
 */

static void
list_node( CTX c, KBNODE node )
{
    int any=0;
    int mainkey;

    if( !node )
	;
    else if( (mainkey = (node->pkt->pkttype == PKT_PUBLIC_KEY) )
	     || node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	PKT_public_key *pk = node->pkt->pkt.public_key;

	if( opt.with_colons ) {
	    u32 keyid[2];
	    keyid_from_pk( pk, keyid );
	    if( mainkey ) {
		c->local_id = pk->local_id;
		c->trustletter = opt.fast_list_mode?
					   0 : get_validity_info( pk, NULL );
	    }
	    printf("%s:", mainkey? "pub":"sub" );
	    if( c->trustletter )
		putchar( c->trustletter );
	    printf(":%u:%d:%08lX%08lX:%s:%s:",
		    nbits_from_pk( pk ),
		    pk->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    colon_datestr_from_pk( pk ),
		    colon_strtime (pk->expiredate) );
	    if( c->local_id )
		printf("%lu", c->local_id );
	    putchar(':');
	    if( mainkey && !opt.fast_list_mode )
                 putchar( get_ownertrust_info (pk) );
	    putchar(':');
	    if( node->next && node->next->pkt->pkttype == PKT_RING_TRUST) {
		putchar('\n'); any=1;
		if( opt.fingerprint )
		    print_fingerprint( pk, NULL, 0 );
		printf("rtv:1:%u:\n",
			    node->next->pkt->pkt.ring_trust->trustval );
	    }
	}
	else
	    printf("%s  %4u%c/%08lX %s ",
				      mainkey? "pub":"sub",
				      nbits_from_pk( pk ),
				      pubkey_letter( pk->pubkey_algo ),
				      (ulong)keyid_from_pk( pk, NULL ),
				      datestr_from_pk( pk )	);

	if( mainkey ) {
	    /* and now list all userids with their signatures */
	    for( node = node->next; node; node = node->next ) {
		if( node->pkt->pkttype == PKT_SIGNATURE ) {
		    if( !any ) {
			if( node->pkt->pkt.signature->sig_class == 0x20 )
			    puts("[revoked]");
			else
			    putchar('\n');
			any = 1;
		    }
		    list_node(c,  node );
		}
		else if( node->pkt->pkttype == PKT_USER_ID ) {
		    if( any ) {
			if( opt.with_colons )
			    printf("%s:::::::::",
			      node->pkt->pkt.user_id->attrib_data?"uat":"uid");
			else
			    printf( "uid%*s", 28, "" );
		    }
		    print_userid( node->pkt );
		    if( opt.with_colons )
			putchar(':');
		    putchar('\n');
		    if( opt.fingerprint && !any )
			print_fingerprint( pk, NULL, 0 );
		    if( node->next
			&& node->next->pkt->pkttype == PKT_RING_TRUST ) {
			printf("rtv:2:%u:\n",
				 node->next->pkt->pkt.ring_trust->trustval );
		    }
		    any=1;
		}
		else if( node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
		    if( !any ) {
			putchar('\n');
			any = 1;
		    }
		    list_node(c,  node );
		}
	    }
	}
	else if( pk->expiredate ) { /* of subkey */
	    printf(_(" [expires: %s]"), expirestr_from_pk( pk ) );
	}

	if( !any )
	    putchar('\n');
	if( !mainkey && opt.fingerprint > 1 )
	    print_fingerprint( pk, NULL, 0 );
    }
    else if( (mainkey = (node->pkt->pkttype == PKT_SECRET_KEY) )
	     || node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
	PKT_secret_key *sk = node->pkt->pkt.secret_key;

	if( opt.with_colons ) {
	    u32 keyid[2];
	    keyid_from_sk( sk, keyid );
	    printf("%s::%u:%d:%08lX%08lX:%s:%s:::",
		    mainkey? "sec":"ssb",
		    nbits_from_sk( sk ),
		    sk->pubkey_algo,
		    (ulong)keyid[0],(ulong)keyid[1],
		    colon_datestr_from_sk( sk ),
		    colon_strtime (sk->expiredate)
		    /* fixme: add LID */ );
	}
	else
	    printf("%s  %4u%c/%08lX %s ",
				      mainkey? "sec":"ssb",
				      nbits_from_sk( sk ),
				      pubkey_letter( sk->pubkey_algo ),
				      (ulong)keyid_from_sk( sk, NULL ),
				      datestr_from_sk( sk )   );
	if( mainkey ) {
	    /* and now list all userids with their signatures */
	    for( node = node->next; node; node = node->next ) {
		if( node->pkt->pkttype == PKT_SIGNATURE ) {
		    if( !any ) {
			if( node->pkt->pkt.signature->sig_class == 0x20 )
			    puts("[revoked]");
			else
			    putchar('\n');
			any = 1;
		    }
		    list_node(c,  node );
		}
		else if( node->pkt->pkttype == PKT_USER_ID ) {
		    if( any ) {
			if( opt.with_colons )
			    printf("%s:::::::::",
			      node->pkt->pkt.user_id->attrib_data?"uat":"uid");
			else
			    printf( "uid%*s", 28, "" );
		    }
		    print_userid( node->pkt );
		    if( opt.with_colons )
			putchar(':');
		    putchar('\n');
		    if( opt.fingerprint && !any )
			print_fingerprint( NULL, sk, 0 );
		    any=1;
		}
		else if( node->pkt->pkttype == PKT_SECRET_SUBKEY ) {
		    if( !any ) {
			putchar('\n');
			any = 1;
		    }
		    list_node(c,  node );
		}
	    }
	}
	if( !any )
	    putchar('\n');
	if( !mainkey && opt.fingerprint > 1 )
	    print_fingerprint( NULL, sk, 0 );
    }
    else if( node->pkt->pkttype == PKT_SIGNATURE  ) {
	PKT_signature *sig = node->pkt->pkt.signature;
	int is_selfsig = 0;
	int rc2=0;
	size_t n;
	char *p;
	int sigrc = ' ';

	if( !opt.list_sigs )
	    return;

	if( sig->sig_class == 0x20 || sig->sig_class == 0x30 )
	    fputs("rev", stdout);
	else
	    fputs("sig", stdout);
	if( opt.check_sigs ) {
	    fflush(stdout);
	    switch( (rc2=do_check_sig( c, node, &is_selfsig, NULL )) ) {
	      case 0:		       sigrc = '!'; break;
	      case G10ERR_BAD_SIGN:    sigrc = '-'; break;
	      case G10ERR_NO_PUBKEY: 
	      case G10ERR_UNU_PUBKEY:  sigrc = '?'; break;
	      default:		       sigrc = '%'; break;
	    }
	}
	else {	/* check whether this is a self signature */
	    u32 keyid[2];

	    if( c->list->pkt->pkttype == PKT_PUBLIC_KEY
		|| c->list->pkt->pkttype == PKT_SECRET_KEY ) {
		if( c->list->pkt->pkttype == PKT_PUBLIC_KEY )
		    keyid_from_pk( c->list->pkt->pkt.public_key, keyid );
		else
		    keyid_from_sk( c->list->pkt->pkt.secret_key, keyid );

		if( keyid[0] == sig->keyid[0] && keyid[1] == sig->keyid[1] )
		    is_selfsig = 1;
	    }
	}
	if( opt.with_colons ) {
	    putchar(':');
	    if( sigrc != ' ' )
		putchar(sigrc);
	    printf("::%d:%08lX%08lX:%s::::", sig->pubkey_algo,
					     (ulong)sig->keyid[0],
		       (ulong)sig->keyid[1], colon_datestr_from_sig(sig));
	}
	else
	    printf("%c       %08lX %s   ",
		    sigrc, (ulong)sig->keyid[1], datestr_from_sig(sig));
	if( sigrc == '%' )
	    printf("[%s] ", g10_errstr(rc2) );
	else if( sigrc == '?' )
	    ;
	else if( is_selfsig ) {
	    if( opt.with_colons )
		putchar(':');
	    fputs( sig->sig_class == 0x18? "[keybind]":"[selfsig]", stdout);
	    if( opt.with_colons )
		putchar(':');
	}
	else if( !opt.fast_list_mode ) {
	    p = get_user_id( sig->keyid, &n );
	    print_string( stdout, p, n, opt.with_colons );
	    m_free(p);
	}
	if( opt.with_colons )
	    printf(":%02x%c:", sig->sig_class, sig->flags.exportable?'x':'l');
	putchar('\n');
    }
    else
	log_error("invalid node with packet of type %d\n", node->pkt->pkttype);
}



int
proc_packets( void *anchor, IOBUF a )
{
    int rc;
    CTX c = m_alloc_clear( sizeof *c );

    c->anchor = anchor;
    rc = do_proc_packets( c, a);
    m_free( c );
    return rc;
}

PKT_signature*
proc_find_signature_packets( IOBUF a, IOBUF buff)
{
    CTX c = m_alloc_clear( sizeof *c );
    int rc;
    KBNODE node;
    PACKET *pkt = m_alloc( sizeof *pkt );
    PKT_signature* tmp = NULL;
    PKT_signature* sig = NULL;
    int i,n;
     int any_data=0;
    int newpkt;

    c->anchor = NULL;
    c->sigs_only = 1;
    c->iobuf = a;
    init_packet(pkt);
    while( (rc=parse_packet(a, pkt)) != -1 ) {
	any_data = 1;
	if( rc ) {
	    free_packet(pkt);
            /* stop processing hwne an invalid packet has been encountered
             * but don't do so when we are doing a --list-packet. */
	    if( rc == G10ERR_INVALID_PACKET && opt.list_packets != 2 )
		break;
	    continue;
	}
	newpkt = -1;
	switch( pkt->pkttype ) {
	case PKT_PUBLIC_KEY:
	case PKT_SECRET_KEY:
	case PKT_USER_ID:
	case PKT_SYMKEY_ENC:
	case PKT_PUBKEY_ENC:
	case PKT_ENCRYPTED:
	case PKT_ENCRYPTED_MDC:
	  write_status_text( STATUS_UNEXPECTED, "0" );
	  rc = G10ERR_UNEXPECTED;
	  break;
	case PKT_SIGNATURE:   newpkt = add_signature( c, pkt ); break;
	case PKT_PLAINTEXT:   proc_plaintext( c, pkt, buff); break;
	case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	case PKT_ONEPASS_SIG: newpkt = add_onepass_sig( c, pkt ); break;
	case PKT_GPG_CONTROL: newpkt = add_gpg_control(c, pkt); break;
	default: newpkt = 0; break;
	}
	if( pkt->pkttype != PKT_SIGNATURE && pkt->pkttype != PKT_MDC )
	    c->have_data = pkt->pkttype == PKT_PLAINTEXT;

	if( newpkt == -1 )
	    ;
	else if( newpkt ) {
	    pkt = m_alloc( sizeof *pkt );
	    init_packet(pkt);
	}
	else
	    free_packet(pkt);
        if ( c->pipemode.stop_now ) {
            /* we won't get an EOF in pipemode, so we have to 
             * break the loop here */ 
            rc = -1;
            break;
        }
    }

    node = c->list;
    while ( node && node->pkt->pkttype != PKT_SIGNATURE ) {
        node = node->next;
    }
    if (node) {
	tmp = node->pkt->pkt.signature;		 
	sig = copy_signature (NULL, tmp);
       

    }

    release_kbnode( c->list );    
    while( c->pkenc_list ) {
	struct kidlist_item *tmp = c->pkenc_list->next;
	m_free( c->pkenc_list );
	c->pkenc_list = tmp;
    }
    c->pkenc_list = NULL;
    c->list = NULL;
    c->have_data = 0;
    c->last_was_session_key = 0;
    c->pipemode.op = 0;
    c->pipemode.stop_now = 0;
    m_free(c->dek); c->dek = NULL;
    m_free( c );
    return sig;
}

int
proc_signature_packets( void *anchor, IOBUF a,
			STRLIST signedfiles, const char *sigfilename )
{
    CTX c = m_alloc_clear( sizeof *c );
    int rc;

    c->anchor = anchor;
    c->sigs_only = 1;
    c->signed_data = signedfiles;
    c->sigfilename = sigfilename;
    rc = do_proc_packets( c, a);
    m_free( c );
    return rc;
}

int
proc_encryption_packets( void *anchor, IOBUF a )
{
    CTX c = m_alloc_clear( sizeof *c );
    int rc;

    c->anchor = anchor;
    c->encrypt_only = 1;
    rc = do_proc_packets( c, a);
    m_free( c );
    return rc;
}


int
do_proc_packets( CTX c, IOBUF a)
{
    PACKET *pkt = m_alloc( sizeof *pkt );
    int rc=0;
    int any_data=0;
    int newpkt;
    int err;

    c->iobuf = a;
    init_packet(pkt);
    while( (rc=parse_packet(a, pkt)) != -1 ) {
	any_data = 1;
	if( rc ) {
	    free_packet(pkt);
            /* stop processing hwne an invalid packet has been encountered
             * but don't do so when we are doing a --list-packet. */
	    if( rc == G10ERR_INVALID_PACKET && opt.list_packets != 2 )
		break;
	    continue;
	}
	newpkt = -1;
	if( opt.list_packets ) {
	    switch( pkt->pkttype ) {
	      case PKT_PUBKEY_ENC:  proc_pubkey_enc( c, pkt ); break;
	      case PKT_SYMKEY_ENC:  proc_symkey_enc( c, pkt ); break;
	      case PKT_ENCRYPTED:
	      case PKT_ENCRYPTED_MDC: proc_encrypted( c, pkt ); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      default: newpkt = 0; break;
	    }
	}
	else if( c->sigs_only ) {
	    switch( pkt->pkttype ) {
	      case PKT_PUBLIC_KEY:
	      case PKT_SECRET_KEY:
	      case PKT_USER_ID:
	      case PKT_SYMKEY_ENC:
	      case PKT_PUBKEY_ENC:
	      case PKT_ENCRYPTED:
	      case PKT_ENCRYPTED_MDC:
                write_status_text( STATUS_UNEXPECTED, "0" );
		rc = G10ERR_UNEXPECTED;
		goto leave;
	      case PKT_SIGNATURE:   newpkt = add_signature( c, pkt ); break;
	      case PKT_PLAINTEXT:   proc_plaintext( c, pkt, NULL); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      case PKT_ONEPASS_SIG: newpkt = add_onepass_sig( c, pkt ); break;
              case PKT_GPG_CONTROL: newpkt = add_gpg_control(c, pkt); break;
	      default: newpkt = 0; break;
	    }
	}
	else if( c->encrypt_only ) {
	    switch( pkt->pkttype ) {
	      case PKT_PUBLIC_KEY:
	      case PKT_SECRET_KEY:
	      case PKT_USER_ID:
                write_status_text( STATUS_UNEXPECTED, "0" );
		rc = G10ERR_UNEXPECTED;
		goto leave;
	      case PKT_SIGNATURE:   newpkt = add_signature( c, pkt ); break;
	      case PKT_SYMKEY_ENC:  proc_symkey_enc( c, pkt ); break;
	      case PKT_PUBKEY_ENC:  proc_pubkey_enc( c, pkt ); break;
	      case PKT_ENCRYPTED:
	      case PKT_ENCRYPTED_MDC: proc_encrypted( c, pkt ); break;
	      case PKT_PLAINTEXT:   proc_plaintext( c, pkt, NULL); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      case PKT_ONEPASS_SIG: newpkt = add_onepass_sig( c, pkt ); break;
	      case PKT_GPG_CONTROL: newpkt = add_gpg_control(c, pkt); break;
	      default: newpkt = 0; break;
	    }
	}
	else {
	    switch( pkt->pkttype ) {
	      case PKT_PUBLIC_KEY:
	      case PKT_SECRET_KEY:
		release_list( c );
		c->list = new_kbnode( pkt );
		newpkt = 1;
		break;
	      case PKT_PUBLIC_SUBKEY:
	      case PKT_SECRET_SUBKEY:
		newpkt = add_subkey( c, pkt );
		break;
	      case PKT_USER_ID:     newpkt = add_user_id( c, pkt ); break;
	      case PKT_SIGNATURE:   newpkt = add_signature( c, pkt ); break;
	      case PKT_PUBKEY_ENC:  proc_pubkey_enc( c, pkt ); break;
	      case PKT_SYMKEY_ENC:  proc_symkey_enc( c, pkt ); break;
	      case PKT_ENCRYPTED:
	      case PKT_ENCRYPTED_MDC: proc_encrypted( c, pkt ); break;
	      case PKT_PLAINTEXT:   proc_plaintext( c, pkt, NULL); break;
	      case PKT_COMPRESSED:  proc_compressed( c, pkt ); break;
	      case PKT_ONEPASS_SIG: newpkt = add_onepass_sig( c, pkt ); break;
              case PKT_GPG_CONTROL: newpkt = add_gpg_control(c, pkt); break;
	      case PKT_RING_TRUST:  newpkt = add_ring_trust( c, pkt ); break;
	      default: newpkt = 0; break;
	    }
	}
        /* This is a very ugly construct and frankly, I don't remember why
         * I used it.  Adding the MDC check here is a hack.
         * The right solution is to initiate another context for encrypted
         * packet and not to reuse the current one ...  It works right
         * when there is a compression packet inbetween which adds just
         * an extra layer.
         * Hmmm: Rewrite this whole module here?? 
         */
	if( pkt->pkttype != PKT_SIGNATURE && pkt->pkttype != PKT_MDC )
	    c->have_data = pkt->pkttype == PKT_PLAINTEXT;

	if( newpkt == -1 )
	    ;
	else if( newpkt ) {
	    pkt = m_alloc( sizeof *pkt );
	    init_packet(pkt);
	}
	else
	    free_packet(pkt);
        if ( c->pipemode.stop_now ) {
            /* we won't get an EOF in pipemode, so we have to 
             * break the loop here */ 
            rc = -1;
            break;
        }
    }

    if( rc == G10ERR_INVALID_PACKET )
	write_status_text( STATUS_NODATA, "3" );
    if( any_data )
	rc = 0;
    else if( rc == -1 )
	write_status_text( STATUS_NODATA, "2" );


  leave:
    
    err = release_list( c );
    if (err) rc = err;
    m_free(c->dek);
    free_packet( pkt );
    m_free( pkt );
    free_md_filter_context( &c->mfx );
    return rc;
}


static int
check_sig_and_print( CTX c, KBNODE node )
{
    PKT_signature *sig = node->pkt->pkt.signature;
    const char *astr, *tstr;
    int rc, is_expkey=0;

    if( opt.skip_verify ) {
	log_info(_("signature verification suppressed\n"));
	return 0;
    }

    /* It is not in all cases possible to check multiple signatures:
     * PGP 2 (which is also allowed by OpenPGP), does use the packet
     * sequence: sig+data,  OpenPGP does use onepas+data=sig and GnuPG
     * sometimes uses (because I did'nt read the specs right) data+sig.
     * Because it is possible to create multiple signatures with
     * different packet sequence (e.g. data+sig and sig+data) it might
     * not be possible to get it right:  let's say we have:
     * data+sig, sig+data,sig+data and we have not yet encountered the last
     * data, we could also see this a one data with 2 signatures and then 
     * data+sig.
     * To protect against this we check that all signatures follow
     * without any intermediate packets.  Note, that we won't get this
     * error when we use onepass packets or cleartext signatures because
     * we reset the list every time
     *
     * FIXME: Now that we have these marker packets, we should create a 
     * real grammar and check against this.
     */
    {
        KBNODE n;
        int n_sig=0;

        for (n=c->list; n; n=n->next ) {
            if ( n->pkt->pkttype == PKT_SIGNATURE ) 
                n_sig++;
        }
        if (n_sig > 1) { /* more than one signature - check sequence */
            int tmp, onepass;

            for (tmp=onepass=0,n=c->list; n; n=n->next ) {
                if (n->pkt->pkttype == PKT_ONEPASS_SIG) 
                    onepass++;
                else if (n->pkt->pkttype == PKT_GPG_CONTROL
                         && n->pkt->pkt.gpg_control->control
                            == CTRLPKT_CLEARSIGN_START ) {
                    onepass++; /* handle the same way as a onepass */
                }
                else if ( (tmp && n->pkt->pkttype != PKT_SIGNATURE) ) {
                    log_error(_("can't handle these multiple signatures\n"));
                    return 0;
                }
                else if ( n->pkt->pkttype == PKT_SIGNATURE ) 
                    tmp = 1;
                else if (!tmp && !onepass 
                         && n->pkt->pkttype == PKT_GPG_CONTROL
                         && n->pkt->pkt.gpg_control->control
                            == CTRLPKT_PLAINTEXT_MARK ) {
                    /* plaintext before signatures but no one-pass packets*/
                    log_error(_("can't handle these multiple signatures\n"));
                    return 0;
                }
            }
        }
    }
    


    tstr = asctimestamp(sig->timestamp);
    astr = pubkey_algo_to_string( sig->pubkey_algo );
    log_info(_("Signature made %.*s using %s key ID %08lX\n"),
	    (int)strlen(tstr), tstr, astr? astr: "?", (ulong)sig->keyid[1] );
   
    rc = do_check_sig(c, node, NULL, &is_expkey );
    if( rc == G10ERR_NO_PUBKEY && opt.keyserver_scheme && opt.keyserver_options.auto_key_retrieve) {
	if( keyserver_import_keyid ( sig->keyid )==0 )
	    rc = do_check_sig(c, node, NULL, &is_expkey );
    }
    if( !rc || rc == G10ERR_BAD_SIGN ) {
	KBNODE un, keyblock;
	int count=0, statno;
        char keyid_str[50];

	if(rc)
	  statno=STATUS_BADSIG;
	else if(sig->flags.expired)
	  statno=STATUS_EXPSIG;
	else if(is_expkey)
	  statno=STATUS_EXPKEYSIG;
	else
	  statno=STATUS_GOODSIG;

	keyblock = get_pubkeyblock( sig->keyid );

        sprintf (keyid_str, "%08lX%08lX [uncertain] ",
                 (ulong)sig->keyid[0], (ulong)sig->keyid[1]);

        /* find and print the primary user ID */
	for( un=keyblock; un; un = un->next ) {
	    if( un->pkt->pkttype != PKT_USER_ID )
		continue;
	    if ( !un->pkt->pkt.user_id->created )
	        continue;
            if ( un->pkt->pkt.user_id->is_revoked )
                continue;
            if ( un->pkt->pkt.user_id->is_expired )
                continue;
	    if ( !un->pkt->pkt.user_id->is_primary )
	        continue;
	    /* We want the textual user ID here */
	    if ( un->pkt->pkt.user_id->attrib_data )
	        continue;
            
            keyid_str[17] = 0; /* cut off the "[uncertain]" part */
            write_status_text_and_buffer (statno, keyid_str,
                                          un->pkt->pkt.user_id->name,
                                          un->pkt->pkt.user_id->len, 
                                          -1 );

            log_info(rc? _("BAD signature from \"")
                       : sig->flags.expired ? _("Expired signature from \"")
		       : _("Good signature from \""));
	    print_utf8_string( log_stream(), un->pkt->pkt.user_id->name,
					     un->pkt->pkt.user_id->len );
	    fputs("\"\n", log_stream() );
            count++;
	}
	if( !count ) {	/* just in case that we have no valid textual
                           userid */
	    /* Try for an invalid textual userid */
            for( un=keyblock; un; un = un->next ) {
                if( un->pkt->pkttype == PKT_USER_ID &&
		    !un->pkt->pkt.user_id->attrib_data )
                    break;
            }

	    /* Try for any userid at all */
	    if(!un) {
	        for( un=keyblock; un; un = un->next ) {
                    if( un->pkt->pkttype == PKT_USER_ID )
                        break;
		}
	    }

            if (opt.always_trust || !un)
                keyid_str[17] = 0; /* cut off the "[uncertain]" part */

            write_status_text_and_buffer (statno, keyid_str,
                                          un? un->pkt->pkt.user_id->name:"[?]",
                                          un? un->pkt->pkt.user_id->len:3, 
                                          -1 );

            log_info(rc? _("BAD signature from \"")
                       : sig->flags.expired ? _("Expired signature from \"")
		       : _("Good signature from \""));
            if (!opt.always_trust && un) {
                fputs(_("[uncertain]"), log_stream() );
                putc(' ', log_stream() );
            }
            print_utf8_string( log_stream(),
                               un? un->pkt->pkt.user_id->name:"[?]",
                               un? un->pkt->pkt.user_id->len:3 );
	    fputs("\"\n", log_stream() );
	}

        /* If we have a good signature and already printed 
         * the primary user ID, print all the other user IDs */
        if ( count && !rc ) {
	    PKT_public_key *pk=NULL;
            for( un=keyblock; un; un = un->next ) {
	        if(un->pkt->pkttype==PKT_PUBLIC_KEY)
  		    pk=un->pkt->pkt.public_key;
                if( un->pkt->pkttype != PKT_USER_ID )
                    continue;
                if ( un->pkt->pkt.user_id->is_revoked )
                    continue;
                if ( un->pkt->pkt.user_id->is_expired )
                    continue;
		/* Only skip textual primaries */
                if ( un->pkt->pkt.user_id->is_primary &&
		     !un->pkt->pkt.user_id->attrib_data )
		    continue;

		if(opt.show_photos && un->pkt->pkt.user_id->attrib_data)
		  show_photos(un->pkt->pkt.user_id->attribs,
			      un->pkt->pkt.user_id->numattribs,pk,NULL);

		log_info(    _("                aka \""));
                print_utf8_string( log_stream(), un->pkt->pkt.user_id->name,
                                                 un->pkt->pkt.user_id->len );
                fputs("\"\n", log_stream() );
            }
	}
	release_kbnode( keyblock );

	if( !rc )
	    print_notation_data( sig );

	if( !rc && is_status_enabled() ) {
	    /* print a status response with the fingerprint */
	    PKT_public_key *pk = m_alloc_clear( sizeof *pk );

	    if( !get_pubkey( pk, sig->keyid ) ) {
		byte array[MAX_FINGERPRINT_LEN], *p;
		char buf[MAX_FINGERPRINT_LEN*2+72];
		size_t i, n;

		fingerprint_from_pk( pk, array, &n );
		p = array;
		for(i=0; i < n ; i++, p++ )
		    sprintf(buf+2*i, "%02X", *p );
		sprintf(buf+strlen(buf), " %s %lu %lu",
					 strtimestamp( sig->timestamp ),
					 (ulong)sig->timestamp,
			                 (ulong)sig->expiredate );
		write_status_text( STATUS_VALIDSIG, buf );
	    }
	    free_public_key( pk );
	}

	if( !rc )
	    rc = check_signatures_trust( sig );

	if(sig->flags.expired)
	  {
	    log_info("Signature expired %s\n",asctimestamp(sig->expiredate));
	    rc=G10ERR_GENERAL; /* need a better error here? */
	  }
	else if(sig->expiredate)
	  log_info("Signature expires %s\n",asctimestamp(sig->expiredate));

	if( rc )
	    g10_errors_seen = 1;
	if( opt.batch && rc )
	    g10_exit(1);
    }
    else {
	char buf[50];
	sprintf(buf, "%08lX%08lX %d %d %02x %lu %d",
		     (ulong)sig->keyid[0], (ulong)sig->keyid[1],
		     sig->pubkey_algo, sig->digest_algo,
		     sig->sig_class, (ulong)sig->timestamp, rc );
	write_status_text( STATUS_ERRSIG, buf );
	if( rc == G10ERR_NO_PUBKEY ) {
	    buf[16] = 0;
	    write_status_text( STATUS_NO_PUBKEY, buf );
	}
	if( rc != G10ERR_NOT_PROCESSED )
	    log_error(_("Can't check signature: %s\n"), g10_errstr(rc) );
    }

    return rc;
}


/****************
 * Process the tree which starts at node
 * Unggul made change here:
 *    I just want to care if signature can be recognized or not.
 *    Return 0 for all other cases and return rc for no recognize
 *    signature
 */
static int
proc_tree( CTX c, KBNODE node )
{
    KBNODE n1;
    int rc = 0;

    if( opt.list_packets || opt.list_only )
	return 0;

    /* we must skip our special plaintext marker packets here becuase
       they may be the root packet.  These packets are only used in
       addionla checks and skipping them here doesn't matter */
    while ( node
            && node->pkt->pkttype == PKT_GPG_CONTROL
            && node->pkt->pkt.gpg_control->control
                         == CTRLPKT_PLAINTEXT_MARK ) {
        node = node->next;
    }
    if (!node)
        return 1;

    c->local_id = 0;
    c->trustletter = ' ';
    if( node->pkt->pkttype == PKT_PUBLIC_KEY
	|| node->pkt->pkttype == PKT_PUBLIC_SUBKEY ) {
	merge_keys_and_selfsig( node );
	list_node( c, node );
    }
    else if( node->pkt->pkttype == PKT_SECRET_KEY ) {
	merge_keys_and_selfsig( node );
	list_node( c, node );
    }
    else if( node->pkt->pkttype == PKT_ONEPASS_SIG ) {
	/* check all signatures */
	if( !c->have_data ) {
	    free_md_filter_context( &c->mfx );
	    /* prepare to create all requested message digests */
	    c->mfx.md = md_open(0, 0);

	    /* fixme: why looking for the signature packet and not 1passpacket*/
	    for( n1 = node; (n1 = find_next_kbnode(n1, PKT_SIGNATURE )); ) {
		md_enable( c->mfx.md, n1->pkt->pkt.signature->digest_algo);
	    }
	    /* ask for file and hash it */
	    if( c->sigs_only ) {
		rc = hash_datafiles( c->mfx.md, NULL,
				     c->signed_data, c->sigfilename,
			n1? (n1->pkt->pkt.onepass_sig->sig_class == 0x01):0 );
	    }
	    else {
		rc = ask_for_detached_datafile( c->mfx.md, c->mfx.md2,
						iobuf_get_real_fname(c->iobuf),
			n1? (n1->pkt->pkt.onepass_sig->sig_class == 0x01):0 );
	    }
	    if( rc ) {
		log_error("can't hash datafile: %s\n", g10_errstr(rc));
		return rc;
	    }
	}
        else if ( c->signed_data ) {
            log_error (_("not a detached signature\n") );
            return 1;
        }
	rc = 9; /* assume that signature not recognized first */
	for( n1 = node; (n1 = find_next_kbnode(n1, PKT_SIGNATURE )); ) {
	    if (rc)
		rc = check_sig_and_print( c, n1 ); // we just need one recognized signature 
	    else check_sig_and_print( c, n1 );
	}
    }
    else if( node->pkt->pkttype == PKT_GPG_CONTROL
             && node->pkt->pkt.gpg_control->control
                == CTRLPKT_CLEARSIGN_START ) {
        /* clear text signed message */
	if( !c->have_data ) {
            log_error("cleartext signature without data\n" );
            return 1;
        }
        else if ( c->signed_data ) {
            log_error (_("not a detached signature\n") );
            return 1;
        }
	rc = 9; // assume no recognized signature first
	for( n1 = node; (n1 = find_next_kbnode(n1, PKT_SIGNATURE )); ){
	    if (rc)
		rc = check_sig_and_print( c, n1 ); // we just need one recognized signature 
	    else check_sig_and_print( c, n1 );
	}	    
    }
    else if( node->pkt->pkttype == PKT_SIGNATURE ) {
	PKT_signature *sig = node->pkt->pkt.signature;

	if( sig->sig_class != 0x00 && sig->sig_class != 0x01 )
	    log_info(_("standalone signature of class 0x%02x\n"),
						    sig->sig_class);
	else if( !c->have_data ) {
	    /* detached signature */
	    free_md_filter_context( &c->mfx );
	    c->mfx.md = md_open(sig->digest_algo, 0);
	    if( !opt.pgp2_workarounds )
		;
	    else if( sig->digest_algo == DIGEST_ALGO_MD5
		     && is_RSA( sig->pubkey_algo ) ) {
		/* enable a workaround for a pgp2 bug */
		c->mfx.md2 = md_open( DIGEST_ALGO_MD5, 0 );
	    }
	    else if( sig->digest_algo == DIGEST_ALGO_SHA1
		     && sig->pubkey_algo == PUBKEY_ALGO_DSA
		     && sig->sig_class == 0x01 ) {
		/* enable the workaround also for pgp5 when the detached
		 * signature has been created in textmode */
		c->mfx.md2 = md_open( sig->digest_algo, 0 );
	    }
	  #if 0 /* workaround disabled */
	    /* Here we have another hack to work around a pgp 2 bug
	     * It works by not using the textmode for detached signatures;
	     * this will let the first signature check (on md) fail
	     * but the second one (on md2) which adds an extra CR should
	     * then produce the "correct" hash.  This is very, very ugly
	     * hack but it may help in some cases (and break others)
	     */
		    /*	c->mfx.md2? 0 :(sig->sig_class == 0x01) */
	  #endif
            if ( DBG_HASHING ) {
                md_start_debug( c->mfx.md, "verify" );
                if ( c->mfx.md2  )
                    md_start_debug( c->mfx.md2, "verify2" );
            }
	    if( c->sigs_only ) {
		rc = hash_datafiles( c->mfx.md, c->mfx.md2,
				     c->signed_data, c->sigfilename,
				     (sig->sig_class == 0x01) );
	    }
	    else {
		rc = ask_for_detached_datafile( c->mfx.md, c->mfx.md2,
						iobuf_get_real_fname(c->iobuf),
						(sig->sig_class == 0x01) );
	    }
	    if( rc ) {
		log_error("can't hash datafile: %s\n", g10_errstr(rc));
		return 1;
	    }
	}
        else if ( c->signed_data ) {
            log_error (_("not a detached signature\n") );
            return 1;
        }
        else if ( c->pipemode.op == 'B' )
            ; /* this is a detached signature trough the pipemode handler */
	else if (!opt.quiet)
	    log_info(_("old style (PGP 2.x) signature\n"));

	rc = 9; // assume no recognized signature first
	for( n1 = node; (n1 = find_next_kbnode(n1, PKT_SIGNATURE )); ){
	    if (rc)
		rc = check_sig_and_print( c, n1 ); // we just need one recognized signature 
	    else check_sig_and_print( c, n1 );
	}	
    }
    else {
        dump_kbnode (c->list);
	log_error(_("invalid root packet detected in proc_tree()\n"));
        dump_kbnode (node);
    }
    return rc;
}




