// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include "minix.h"
#include <linux/fs.h>
#include <linux/uio.h>
#include <asm/uaccess.h>       
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <crypto/internal/skcipher.h>	//usado para o AES
#include <linux/crypto.h>	//usado para o AES
#define SHA256_LENGTH 32	// tamanho da mensagem

static ssize_t read_crypto(struct kiocb *iocb, struct iov_iter *iter);
static ssize_t write_crypto(struct kiocb *iocb, struct iov_iter *from);
static int encryptBuffer(char * bufferAux);
static int decryptBuffer(char * bufferAux);
static int test_skcipher(void);

static char *myKey = "00000000000000000000000000000011"; // criando a variavel para ler a chave inserida pelo usuario
static struct skcipher_def sk;
static struct crypto_skcipher *skcipher = NULL;
static struct skcipher_request *req = NULL;
static char *scratchpad = NULL;
static unsigned char key[16];


/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= read_crypto,
	.write_iter	= write_crypto,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct crypto_wait wait;
};



static unsigned int test_skcipher_encdec(struct skcipher_def *sk,int enc)
{
    int rc;

    if (enc!=0)
        rc = crypto_wait_req(crypto_skcipher_encrypt(sk->req), &sk->wait);
    else
        rc = crypto_wait_req(crypto_skcipher_decrypt(sk->req), &sk->wait);

    if (rc)
            pr_info("skcipher encrypt returned with result %d\n", rc);

    return rc;
}

static ssize_t read_crypto(struct kiocb *iocb, struct iov_iter *iter)
{
	int ret;
	char *data = (char *)iter->kvec->iov_base;

	test_skcipher();


	ret = generic_file_read_iter(iocb, iter);


	decryptBuffer(data);
	sprintf(data,"%s",scratchpad);

	printk("Estou lendo %s\n",data);
	return ret;
}

static int decryptBuffer(char * bufferAux){

	int ret = -EFAULT;

	test_skcipher();
	for(ret = 0; ret < 16; ret++){
	scratchpad[ret] = 0;
	}
	for(ret = 0; ret < 16; ret++){
	scratchpad[ret] = bufferAux[ret];
	}

    ret = test_skcipher_encdec(&sk, 0);

    sg_copy_from_buffer(&sk.sg, 1, scratchpad, 16);

	scratchpad[strlen(scratchpad)+1] = '\0';



return ret;
}

static ssize_t write_crypto(struct kiocb *iocb, struct iov_iter *from)
{
	int ret,i;
	char *data = (char *)from->kvec->iov_base;

	test_skcipher();

	encryptBuffer(data);
	sprintf(data,"%s",scratchpad);

	ret = generic_file_write_iter(iocb, from);

	for(i = 0; i<16; i++){
	    //pr_info("%02hhX",(unsigned char)data[i]);
	}
	    pr_info("Estou escrevendo %s \n",data);

	return ret;
}

static int encryptBuffer(char * bufferAux){
    /* We encrypt one block */
	int ret = -EFAULT;

  
	for(ret = 0; ret < 16; ret++){
	scratchpad[ret] = 0;
	}

	sprintf(scratchpad,"%s",bufferAux);
    	ret = test_skcipher_encdec(&sk, 1);

return ret;
}

static int mudar_chave(void){
int i,j;
j = 0;

	for(i=0;i < 16;i++){
		key[i]=0;		
	}

	if(strlen(myKey) < 32 ){

		for(i = 0; i < strlen(myKey)/2; i++){
			if(myKey[j] < 64 && myKey[j+1] < 64){
				key[i] = 16*(myKey[j]-48) + (myKey[j+1]-48);
			}
			else{
				if(myKey[j] > 64 && myKey[j+1] < 64){
				key[i] = 16*(myKey[j]-55) + (myKey[j+1]-48);
				}
				else{
					if(myKey[j] < 64 && myKey[j+1] > 64){
					key[i] = 16*(myKey[j]-48) + (myKey[j+1]-55);
					}
					else{
						key[i] = 16*(myKey[j]-64) + (myKey[j+1]-55);						
					}
				}
			}

		j+=2;
		}


		pr_info("A Chave inserida eh muito pequena por isso foram adicionados 0 ao seu final: "); //Chave com padding
		for(j = 0; j<16; j++){
	    		pr_info("%d %02hhX",j, (unsigned char)key[j]);
		}

	}else{

		for(i = 0; i<16;i++){
			if(myKey[j] < 64 && myKey[j+1] < 64){
				key[i] = 16*(myKey[j]-48) + (myKey[j+1]-48);
			}
			else{
				if(myKey[j] > 64 && myKey[j+1] < 64){
				key[i] = 16*(myKey[j]-55) + (myKey[j+1]-48);
				}
				else{
					if(myKey[j] < 64 && myKey[j+1] > 64){
					key[i] = 16*(myKey[j]-48) + (myKey[j+1]-55);
					}
					else{
						key[i] = 16*(myKey[j]-55) + (myKey[j+1]-55);						
					}
				}
			}
		j+=2;

		}

	}
}



static int test_skcipher(void)
{

    int ret = -EFAULT;
    skcipher = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0);

	mudar_chave();
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

	/* Setando a chave*/

    if (crypto_skcipher_setkey(skcipher, key, 16)) { 
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* Alocar mensagem do usuario */
    scratchpad = kmalloc(16, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
	/* Inserir 16 bytes de dados da mensagem do usuario */
	

    sk.tfm = skcipher;
    sk.req = req;
    sg_init_one(&sk.sg, scratchpad, 16);

    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, 0);
    crypto_init_wait(&sk.wait);
	    		
out:
return 0;

}



static int minix_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		minix_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations minix_file_inode_operations = {
	.setattr	= minix_setattr,
	.getattr	= minix_getattr,
};
