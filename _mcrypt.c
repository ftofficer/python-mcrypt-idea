/*

python-mcrypt - python mcrypt library interface

Copyright (c) 2002  Gustavo Niemeyer <niemeyer@conectiva.com>

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include <mcrypt.h>
#include "Python.h"
#include "structmember.h"

/* Thread support doesn't seem to be working in mcrypt */
#undef WITH_THREAD
#ifdef WITH_THREAD
#include "pythread.h"
#endif

static char __author__[] =
"The mcrypt python module was developed by:\n\
\n\
    Gustavo Niemeyer <niemeyer@conectiva.com>\n\
";

static PyObject *MCRYPTError;

/* Keep directories somewhere to avoid entering them every time a
 * MCRYPT object is instantiated. */
static char *algorithm_dir = NULL;
static char *mode_dir = NULL;

#define INIT_NONE    0
#define INIT_ANY     1
#define INIT_ENCRYPT 2
#define INIT_DECRYPT 3
#define INIT_REINIT  4
#define INIT_DEINIT  5

typedef struct {
	PyObject_HEAD
	MCRYPT thread;
	char *algorithm;
	char *mode;
	int init;
	void *init_iv;
	void *init_key;
	int init_key_size;
	int block_mode;
	int block_size;
	int iv_size;
} MCRYPTObject;

#define OFF(x) offsetof(MCRYPTObject, x)

static PyMemberDef MCRYPT_members[] = {
	{"algorithm",     T_STRING, OFF(algorithm),     READONLY},
	{"mode",          T_STRING, OFF(mode),          READONLY},
	{0}
};

staticforward PyTypeObject MCRYPT_Type;

#define MCRYPTObject_Check(v)	((v)->ob_type == &MCRYPT_Type)

static int
catch_mcrypt_error(int rc)
{
	const char *error;
	char *myerror;
	int ret = 0;
	if (rc < 0) {
		error = mcrypt_strerror(rc);
		if (error != NULL) {
			/* "Error message.\n" -> "error message" */
			myerror = strdup(error);
			myerror[strlen(myerror)-2] = 0;
			myerror[0] += 'a'-'A';
			PyErr_SetString(MCRYPTError, myerror);
			free(myerror);
		} else {
			PyErr_SetString(MCRYPTError, "unknown mcrypt error");
		}
		ret = 1;
	}
	return ret;
}

static int
get_iv_from_obj(MCRYPTObject *self, PyObject *ivobj, void **iv)
{
	if (ivobj == Py_None) {
		*iv = NULL;
	} else if (PyString_Check(ivobj)) {
		int iv_size = PyString_Size(ivobj);
		*iv = PyString_AsString(ivobj);
		if (iv_size != self->iv_size) {
			PyErr_Format(PyExc_ValueError,
				     "iv size for this algorithm must be %d",
				     self->iv_size);
			return 0;
		}
	} else {
		PyErr_SetString(PyExc_TypeError,
				"iv must be None or a string");
		return 0;
	}
	return 1;
}

static int
check_algorithm(char *name, char *dir)
{
	char **algorithms;
	int size;
	int i;
	algorithms = mcrypt_list_algorithms(dir, &size);
	if (algorithms != NULL)
		for (i = 0; i != size; i++)
			if (strcmp(name, algorithms[i]) == 0) {
				mcrypt_free_p(algorithms, size);
				return 1;
			}
	mcrypt_free_p(algorithms, size);
	return 0;
}

static int
check_mode(char *name, char *dir)
{
	char **modes;
	int size;
	int i;
	modes = mcrypt_list_modes(dir, &size);
	if (modes != NULL)
		for (i = 0; i != size; i++)
			if (strcmp(name, modes[i]) == 0) {
				mcrypt_free_p(modes, size);
				return 1;
			}
	mcrypt_free_p(modes, size);
	return 0;
}

static int
check_key(MCRYPTObject *self, char *key, int key_size)
{
	int max_key_size;
	int *key_sizes;
	int size;
	int i;
	
	if (key == NULL || key_size == 0) {
		PyErr_SetString(PyExc_ValueError, "you must provide a key");
		return 0;
	}

	max_key_size = mcrypt_enc_get_key_size(self->thread);
	if (catch_mcrypt_error(max_key_size))
		return 0;

	if (key_size > max_key_size) {
		PyErr_SetString(PyExc_ValueError, "invalid key length");
		return 0;
	}

	key_sizes = mcrypt_enc_get_supported_key_sizes(self->thread, &size);
	if (key_sizes != NULL) {
		int ret = 0;
		for (i = 0; i != size; i++)
			if (key_sizes[i] == key_size) {
				ret = 1;
				break;
			}
		mcrypt_free(key_sizes);
		if (ret == 0)
			PyErr_SetString(PyExc_ValueError,
					"invalid key length");
		return ret;
	}

	return 1;
}

/* This is where the init magic takes place. It will do its best to
 * be as fast as possible, and try hard to avoid asking the user for
 * another hard init. Note that iv must have the size expected by the
 * algorithm. */
static int
init_mcrypt(MCRYPTObject *self, int type,
	    void *key, int key_size,
            void *iv)
{
	register int action = INIT_NONE;
	register int curtype = self->init;
	
	/* In this switch action will be set to NONE, ANY, DEINIT, or REINIT
	 * depending on the current value of type, and the requested type. */
	switch (type) {
		/* case INIT_NONE: Must never happen. */

		case INIT_ANY:
			if (!check_key(self, key, key_size))
				return 0;
			action = INIT_ANY;
			break;

		case INIT_ENCRYPT:
		case INIT_DECRYPT:
			if (curtype == type || curtype == INIT_ANY) {
				action = INIT_NONE;
				self->init = type;
			} else if (curtype != INIT_NONE) {
				/* We could reinit automatically, but this
				 * seem to confuse more than help. */
				/* action = INIT_REINIT; */
				PyErr_SetString(MCRYPTError,
						"reinit/init method not run");
				return 0;
			} else {
				PyErr_SetString(MCRYPTError,
						"init method not run");
				return 0;
			}
			break;
			
		case INIT_REINIT:
			if (curtype == INIT_NONE) {
				PyErr_SetString(MCRYPTError,
						"reinit called without a "
						"previous init");
				return 0;
			}
			action = INIT_REINIT;
			break;

		case INIT_DEINIT:
			action = INIT_DEINIT;
			break;
	}
	
	if (action == INIT_REINIT) {
		/* Try a quick reinit. If it fails, fallback to a hard
		 * reinit. */
		int rc = mcrypt_enc_set_state(self->thread, self->init_iv,
					      self->iv_size);
		if (rc == 0) {
			self->init = INIT_ANY;
		} else {
			int rc = mcrypt_generic_deinit(self->thread);
			if (catch_mcrypt_error(rc))
				return 0;
			rc = mcrypt_generic_init(self->thread,
						 self->init_key,
						 self->init_key_size,
						 self->init_iv);	
			if (catch_mcrypt_error(rc)) {
				self->init = INIT_NONE;
				PyMem_Free(self->init_iv);
				PyMem_Free(self->init_key);
				self->init_iv = NULL;
				self->init_key = NULL;
				self->init_key_size = 0;
				return 0;
			}
			self->init = INIT_ANY;
		}
	} else if (action == INIT_ANY || action == INIT_DEINIT) {
		self->init = INIT_NONE;
		PyMem_Free(self->init_iv);
		PyMem_Free(self->init_key);
		self->init_iv = NULL;
		self->init_key = NULL;
		self->init_key_size = 0;

		if (curtype != INIT_NONE) {
			int rc = mcrypt_generic_deinit(self->thread);
			if (catch_mcrypt_error(rc))
				return 0;
		}

		if (action == INIT_ANY) {
			int rc;
			self->init_key = PyMem_Malloc(key_size);
			if (self->init_key == NULL) {
				PyErr_NoMemory();
				return 0;
			}
			memcpy(self->init_key, key, key_size);
			self->init_iv = PyMem_Malloc(self->iv_size);
			if (self->init_iv == NULL) {
				PyErr_NoMemory();
				return 0;
			}
			if (iv) {
				memcpy(self->init_iv, iv, self->iv_size);
			} else {
				memset(self->init_iv, 0, self->iv_size);
			}
			rc = mcrypt_generic_init(self->thread, key, key_size,
						 iv);	
			if (catch_mcrypt_error(rc)) {
				PyMem_Free(self->init_iv);
				PyMem_Free(self->init_key);
				self->init_iv = NULL;
				self->init_key = NULL;
				return 0;
			}
			self->init_key_size = key_size;
			self->init = INIT_ANY;
		}
	}
	return 1;
}

static void
MCRYPT_dealloc(MCRYPTObject *self)
{
	if (self->thread) {
		if (self->init != INIT_NONE) {
			if (!init_mcrypt(self, INIT_DEINIT, NULL, 0, NULL))
				PyErr_Clear();
		}
		mcrypt_module_close(self->thread);
		free(self->algorithm);
		free(self->mode);
	}
	self->ob_type->tp_free((PyObject *)self);
}

static int
MCRYPT__init__(MCRYPTObject *self, PyObject *args, PyObject *kwargs)
{
	char *algorithm;
	char *mode;
	char *adir;
	char *mdir;
	PyObject *aobj = NULL;
	PyObject *mobj = NULL;
	int blk_alg, blk_alg_mode;

	char *kwlist[] = {"algorithm", "mode", "algorithm_dir", "mode_dir", 0};

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ss|OO:__init__", kwlist,
					 &algorithm, &mode, &aobj, &mobj))
		return -1;

	if (aobj == NULL) {
		adir = algorithm_dir;
	} else if (aobj == Py_None) {
		adir = NULL;
	} else if (PyString_Check(aobj)) {
		adir = PyString_AsString(aobj);
	} else {
		PyErr_SetString(PyExc_TypeError,
				"algorithm_dir must be None or a string");
		return -1;
	}

	if (mobj == NULL) {
		mdir = mode_dir;
	} else if (mobj == Py_None) {
		mdir = NULL;
	} else if (PyString_Check(mobj)) {
		mdir = PyString_AsString(mobj);
	} else {
		PyErr_SetString(PyExc_TypeError,
				"mode_dir must be None or a string");
		return -1;
	}

	/* These checks consume processor time, but the mcrypt library is
	 * quite fragile, and will segfault easily if wrong parameters are
	 * used. */
	if (!check_algorithm(algorithm, adir)) {
		PyErr_SetString(MCRYPTError, "unknown algorithm module");
		return -1;
	}
	if (!check_mode(mode, mdir)) {
		PyErr_SetString(MCRYPTError, "unknown mode module");
		return -1;
	}
	
	blk_alg = mcrypt_module_is_block_algorithm(algorithm, adir);
	if (catch_mcrypt_error(blk_alg))
		return -1;
	blk_alg_mode = mcrypt_module_is_block_algorithm_mode(mode, mdir);
	if (catch_mcrypt_error(blk_alg_mode))
		return -1;
	
	if (blk_alg != blk_alg_mode) {
		char *msg[] = {"block mode used with stream algorithm",
			       "stream mode used with block algorithm"};
		PyErr_SetString(MCRYPTError, msg[blk_alg]);
		return -1;
	}

	self->thread = mcrypt_module_open(algorithm, adir, mode, mdir);

	if (self->thread == MCRYPT_FAILED) {
		PyErr_SetString(MCRYPTError, "unknown mcrypt error");
		return -1;
	}
	
	self->block_mode = mcrypt_enc_is_block_mode(self->thread);
	if (catch_mcrypt_error(self->block_mode)) {
		mcrypt_module_close(self->thread);
		return -1;
	}
	self->block_size = mcrypt_enc_get_block_size(self->thread);
	if (catch_mcrypt_error(self->block_size)) {
		mcrypt_module_close(self->thread);
		return -1;
	}
	self->iv_size = mcrypt_enc_get_iv_size(self->thread);
	if (catch_mcrypt_error(self->iv_size)) {
		mcrypt_module_close(self->thread);
		return -1;
	}
	
	self->algorithm = strdup(algorithm);
	self->mode = strdup(mode);

	return 0;
}

static char MCRYPT_init__doc__[] =
"init(key [, iv]) -> None\n\
\n\
This method initializes all buffers for the MCRYPT instance. The\n\
maximum length of key should be the one obtained by calling\n\
MCRYPT.get_key_size(). You must also check MCRYPT.get_key_sizes(),\n\
which will return an empty list, if every value smaller than the\n\
maximum length is legal, or a list of legal key lengths. Note that the\n\
key length is specified in bytes not bits. The iv parameter, if given,\n\
must have the size obtained with MCRYPT.get_iv_size().  It needs to be\n\
random and unique (but not secret). The same iv must be used for\n\
encryption/decryption. Even if this parameter is not obligatory, its\n\
use is recommended.  You must call this function before starting to\n\
encrypt or decrypt something. If you want to use the same key and iv\n\
to encrypt and/or decrypt data repeatedly, you may use MCRYPT.reinit()\n\
as a faster alternative.\n\
";

static PyObject *
MCRYPT_init(MCRYPTObject *self, PyObject *args, PyObject *kwargs)
{
	void *key, *iv;
	int key_size;
	PyObject *ivobj = Py_None;

	static char *kwlist[] = {"key", "iv", 0};
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#|O:init",
					 kwlist, &key, &key_size, &ivobj))
		return NULL;

	if (!get_iv_from_obj(self, ivobj, &iv))
		return NULL;

	if (!init_mcrypt(self, INIT_ANY, key, key_size, iv))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}

static char MCRYPT_reinit__doc__[] =
"reinit() -> None\n\
\n\
If you have encrypted or decrypted something and want to encrypt\n\
or decrypt something else with the same key and iv, you may use\n\
this method as a faster alternative to using init() with the same\n\
parameters as before. Note that you can't call this method in an\n\
uninitialized instance.\n\
";

static PyObject *
MCRYPT_reinit(MCRYPTObject *self, PyObject *args)
{
	if (!init_mcrypt(self, INIT_REINIT, NULL, 0, NULL))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}

static char MCRYPT_deinit__doc__[] =
"deinit() -> None\n\
\n\
This method clear all buffers and deinitialize the instance. After\n\
calling it you won't be able to use the reinit() method, and will have\n\
to call init() if you want to use one of the encrypt or decrypt methods.\n\
\n\
Calling this method is optional.\n\
";

static PyObject *
MCRYPT_deinit(MCRYPTObject *self, PyObject *args)
{
	if (!init_mcrypt(self, INIT_DEINIT, NULL, 0, NULL))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}

static char MCRYPT_encrypt__doc__[] =
"encrypt(data [, fixlength=0]) -> encrypted_data\n\
\n\
This is the main encryption function. If using a block algorithm, and\n\
data size is not a multiple of the block size, data will be padded\n\
with zeros before the encryption. If fixlength is 1 than a trick will\n\
be used to keep the original data size when decrypting. This trick\n\
consists of using the last byte to keep the number of used bytes in\n\
the last block (when all bytes are used, an empty block has to be\n\
added to support this). Note that for the trick to work, you must\n\
enable it in decryption as well (to understand the trick, you may want\n\
to enable it for encrypt, and not for decrypt).\n\
";

static PyObject *
MCRYPT_encrypt(MCRYPTObject *self, PyObject *args, PyObject *kwargs)
{
	void *blockbuffer, *data;
	int blockbuffer_size, data_size;
	int numblocks, left_size, block_size;
	int fixlength = 0;
	int rc;
	PyObject *ret;

	static char *kwlist[] = {"data", "fixlength", 0};
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#|i:encrypt",
					 kwlist, &data, &data_size, &fixlength))
		return NULL;

	if (self->block_mode) {
		block_size = self->block_size;
	} else {
		block_size = 1;
		fixlength = 0;
	}

	if (!init_mcrypt(self, INIT_ENCRYPT, NULL, 0, NULL))
		return NULL;

	numblocks = data_size/block_size+1;
	left_size = data_size%block_size;
	if (!fixlength && left_size == 0)
		numblocks--;
	blockbuffer_size = numblocks * block_size;
	blockbuffer = PyMem_Malloc(blockbuffer_size);
	if (blockbuffer == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	memset(blockbuffer, 0, blockbuffer_size);
	if (fixlength)
		((char *)blockbuffer)[blockbuffer_size-1] = left_size;
	memcpy(blockbuffer, data, data_size);
	rc = mcrypt_generic(self->thread, blockbuffer, blockbuffer_size);
	if (catch_mcrypt_error(rc))
		ret = NULL;
	else
		ret = PyString_FromStringAndSize(blockbuffer,
						 blockbuffer_size);
	PyMem_Free(blockbuffer);
	return ret;
}

static char MCRYPT_decrypt__doc__[] =
"decrypt(data [, fixlength=0]) -> decrypted_data\n\
\n\
This is the main decryption function. If fixlength is 1 than a trick\n\
will be used to keep the original data size when decrypting. This\n\
trick consists of using the last byte to keep the number of used bytes\n\
in the last block (when all bytes are used, an empty block has to be\n\
added to support this). Note that for the trick to work, you must\n\
enable it in encryption as well (to understand the trick, you may want\n\
to enable it for encrypt, and not for decrypt).\n\
";

static PyObject *
MCRYPT_decrypt(MCRYPTObject *self, PyObject *args, PyObject *kwargs)
{
	void *blockbuffer, *data;
	int blockbuffer_size, data_size;
	int numblocks, left_size, block_size;
	int fixlength = 0;
	int rc;
	PyObject *ret;
	
	static char *kwlist[] = {"data", "fixlength", 0};
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#|i:decrypt",
					 kwlist, &data, &data_size,
					 &fixlength))
		return NULL;

	if (self->block_mode) {
		block_size = self->block_size;
	} else {
		block_size = 1;
		fixlength = 0;
	}

	if (!init_mcrypt(self, INIT_DECRYPT, NULL, 0, NULL))
		return NULL;
	
	numblocks = data_size/block_size;
	blockbuffer_size = numblocks * block_size;
	blockbuffer = PyMem_Malloc(blockbuffer_size);
	if (blockbuffer == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	memcpy(blockbuffer, data, data_size);
	rc = mdecrypt_generic(self->thread, blockbuffer,
			      blockbuffer_size);
	if (fixlength) {
		left_size = ((char *)blockbuffer)[blockbuffer_size-1];
		if (left_size > block_size)
			/* Oops! Wrong key or data without fixlength. */
			left_size = block_size;
	} else {
		left_size = block_size;
	}
	if (catch_mcrypt_error(rc))
		ret = NULL;
	else
		ret = PyString_FromStringAndSize(blockbuffer, blockbuffer_size
						 -block_size+left_size);
	PyMem_Free(blockbuffer);
	return ret;
}

static char MCRYPT_encrypt_file__doc__[] =
"encrypt_file(filein, fileout\n\
	      [, fixlength=1, bufferblocks=1024]) -> encrypted_data\n\
\n\
You may use this function to encrypt files. If using a block algorithm,\n\
and data size is not a multiple of the block size, data will be padded\n\
with zeros before the encryption. If fixlength is 1 than a trick will\n\
be used to keep the original data size when decrypting. This trick\n\
consists of using the last byte to keep the number of used bytes in\n\
the last block (when all bytes are used, an empty block has to be\n\
added to support this). Note that for the trick to work, you must\n\
enable it in decryption as well (to understand the trick, you may want\n\
to enable it for encrypt, and not for decrypt). The bufferblocks\n\
parameter allows you to set the buffer size that will be used to\n\
transfer data between the files (buffer_size = bufferblocks*block_size).\n\
";

static PyObject *
MCRYPT_encrypt_file(MCRYPTObject *self, PyObject *args, PyObject *kwargs)
{
	void *blockbuffer, *data;
	int blockbuffer_size, datablock_size, data_size;
	int numblocks;
	int fixlength = 1;
	int bufferblocks = 1024;
	PyObject *filein;
	PyObject *fileout;
	PyObject *readmeth;
	PyObject *writemeth;
	int error = 0;

	static char *kwlist[] = {"filein", "fileout", "fixlength",
				 "bufferblocks", 0};
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|ii:encrypt_file",
					 kwlist, &filein, &fileout,
					 &fixlength, &bufferblocks))
		return NULL;

	if (!init_mcrypt(self, INIT_ENCRYPT, NULL, 0, NULL))
		return NULL;

	readmeth = PyObject_GetAttrString(filein, "read");
	if (readmeth == NULL)
		return NULL;
	writemeth = PyObject_GetAttrString(fileout, "write");
	if (writemeth == NULL)
		return NULL;
	
	blockbuffer_size = bufferblocks*self->block_size;
	blockbuffer = PyMem_Malloc(blockbuffer_size);
	if (blockbuffer == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	while (1) {
		PyObject *result;
		int left_size = 0;
		int rc;

		result = PyEval_CallFunction(readmeth, "(i)", blockbuffer_size);
		if (result == NULL) {
			error = 1;
			break;
		}

		if (!PyString_Check(result)) {
			Py_DECREF(result);
			PyErr_SetString(PyExc_TypeError,
					"read method must return strings");
			error = 1;
			break;
		}
		
		data = PyString_AsString(result);
		data_size = PyString_Size(result);
		
		/* If we're using fixlength and left_size
		 * was 0 last time, we must add a pad to insert
		 * the left_size, because we were not able to do
		 * this in the last encrypted block. */
		if (data_size == 0 && (!fixlength || left_size != 0)) {
			Py_DECREF(result);
			break;
		}
		
		numblocks = data_size/self->block_size;
		left_size = data_size%self->block_size;
		
		/* If data_size is 0, it means we're adding an
		 * empty block just to save the left_size byte. */
		if (left_size || data_size == 0) {
			numblocks++;
			datablock_size = numblocks*self->block_size;
			memset(blockbuffer, 0, datablock_size);
			if (fixlength)
				((char *)blockbuffer)[datablock_size-1]
					= left_size;
		} else {
			datablock_size = numblocks*self->block_size;
		}
		
		memcpy(blockbuffer, data, data_size);
		Py_DECREF(result);

		rc = mcrypt_generic(self->thread, blockbuffer,
				    datablock_size);
		if (catch_mcrypt_error(rc)) {
			error = 1;
			break;
		}

		result = PyEval_CallFunction(writemeth, "(s#)",
					     blockbuffer,
					     datablock_size);
		Py_XDECREF(result);
		if (result == NULL) {
			error = 1;
			break;
		}

		/* The data_size variable will only be 0 here if we
		 * have just inserted a blank block to save the
		 * left_size byte. */
		if (left_size != 0 || data_size == 0)
			break;
	}
	
	Py_DECREF(readmeth);
	Py_DECREF(writemeth);
	PyMem_Free(blockbuffer);
	
	if (error)
		return NULL;
	
	Py_INCREF(Py_None);
	return Py_None;
}

static char MCRYPT_decrypt_file__doc__[] =
"decrypt_file(filein, fileout\n\
	      [, fixlength=1, bufferblocks=1024]) -> decrypted_data\n\
\n\
You may use this function to decrypt files. If fixlength is 1 than a\n\
trick will be used to keep the original data size when decrypting. This\n\
trick consists of using the last byte to keep the number of used bytes\n\
in the last block (when all bytes are used, an empty block has to be\n\
added to support this). Note that for the trick to work, you must\n\
enable it in encryption as well (to understand the trick, you may want\n\
to enable it for encrypt, and not for decrypt). The bufferblocks\n\
parameter allows you to set the buffer size that will be used to\n\
transfer data between the files (buffer_size = bufferblocks*block_size).\n\
";

static PyObject *
MCRYPT_decrypt_file(MCRYPTObject *self, PyObject *args, PyObject *kwargs)
{
	void *blockbuffer, *data;
	int blockbuffer_size, datablock_size, data_size;
	int fixlength = 1;
	int bufferblocks = 1024;
	int numblocks;

	PyObject *filein;
	PyObject *fileout;
	PyObject *readmeth;
	PyObject *writemeth;
	PyObject *nextresult = NULL;

	int error = 0;

	static char *kwlist[] = {"filein", "fileout", "fixlength",
				 "bufferblocks", 0};
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO|ii:decrypt_file",
					 kwlist, &filein, &fileout,
					 &fixlength, &bufferblocks))
		return NULL;

	if (!init_mcrypt(self, INIT_DECRYPT, NULL, 0, NULL))
		return NULL;

	readmeth = PyObject_GetAttrString(filein, "read");
	if (readmeth == NULL)
		return NULL;
	writemeth = PyObject_GetAttrString(fileout, "write");
	if (writemeth == NULL)
		return NULL;
	
	blockbuffer_size = bufferblocks*self->block_size;
	blockbuffer = PyMem_Malloc(blockbuffer_size);
	if (blockbuffer == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	
	/* We have to keep the next result to be able to
	 * know when we are processing the last exact blockbuffer,
	 * and this way do not save the padding in the last block. */
	nextresult = PyEval_CallFunction(readmeth, "(i)",
					 blockbuffer_size);
	while (1) {
		PyObject *result;
		int left_size;
		int last = 0;
		int rc;

		result = nextresult;
		if (result == NULL) {
			error = 1;
			break;
		}

		nextresult = PyEval_CallFunction(readmeth, "(i)",
						 blockbuffer_size);

		if (nextresult != NULL && PyString_Check(nextresult)
		    && PyString_Size(nextresult) == 0)
			last = 1;

		if (!PyString_Check(result)) {
			Py_DECREF(result);
			PyErr_SetString(PyExc_TypeError,
					"read method must return strings");
			error = 1;
			break;
		}

		data = PyString_AsString(result);
		data_size = PyString_Size(result);
		if (data_size == 0) {
			Py_DECREF(result);
			break;
		}
		
		numblocks = data_size/self->block_size;
		datablock_size = numblocks*self->block_size;
		
		memcpy(blockbuffer, data, datablock_size);
		Py_DECREF(result);

		rc = mdecrypt_generic(self->thread, blockbuffer,
				      datablock_size);
		if (catch_mcrypt_error(rc)) {
			error = 1;
			break;
		}
		
		if (!fixlength || (datablock_size == blockbuffer_size
				   && !last)) {
			left_size = self->block_size;
		} else {
			left_size = ((char *)blockbuffer)[datablock_size-1];
			if (left_size > self->block_size)
				/* Oops! Wrong key or not fixlength data. */
				left_size = self->block_size;
		}
		
		result = PyEval_CallFunction(writemeth, "(s#)",
					     blockbuffer,
					     datablock_size-
					     self->block_size+left_size);
		Py_XDECREF(result);
		if (result == NULL) {
			error = 1;
			break;
		}
		if (left_size != self->block_size)
			break;
	}
	Py_XDECREF(nextresult);
	Py_DECREF(readmeth);
	Py_DECREF(writemeth);
	PyMem_Free(blockbuffer);

	if (error)
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}

static char MCRYPT_get_block_size__doc__[] =
"get_block_size() -> block_size\n\
\n\
Returns the block size of the algorithm used by the instance.\n\
";

static PyObject *
MCRYPT_get_block_size(MCRYPTObject *self, PyObject *args)
{
	return PyInt_FromLong(self->block_size);
}

static char MCRYPT_get_key_size__doc__[] =
"get_key_size() -> key_size\n\
\n\
This method returns the maximum key size supported by the algorithm\n\
used in the MCRYPT instance. To know the acceptable key sizes, you must\n\
check the get_key_sizes() method.\n\
";

static PyObject *
MCRYPT_get_key_size(MCRYPTObject *self, PyObject *args)
{
	int rc = mcrypt_enc_get_key_size(self->thread);
	if (catch_mcrypt_error(rc))
		return NULL;
	return PyInt_FromLong(rc);
}

static char MCRYPT_get_key_sizes__doc__[] =
"get_key_sizes() -> key_size_list\n\
\n\
This method returns a list of key sizes supported by the algorithm\n\
used in the MCRYPT instance. If this list is empty, any length between\n\
1 and the maximum key size (returned by the get_key_size() function)\n\
may be used.\n\
";

static PyObject *
MCRYPT_get_key_sizes(MCRYPTObject *self, PyObject *args)
{
	int *key_sizes;
	int size;
	int i;
	PyObject *ret;
	key_sizes = mcrypt_enc_get_supported_key_sizes(self->thread, &size);
	ret = PyList_New(size);
	if (ret != NULL)
		for (i = 0; i != size; i++) {
			PyObject *o = PyInt_FromLong(key_sizes[i]);
			if (o == NULL) {
				PyObject_Del(o);
				ret = NULL;
				break;
			}
			PyList_SetItem(ret, i, o);
		}
	mcrypt_free(key_sizes);
	return ret;
}

static char MCRYPT_has_iv__doc__[] =
"has_iv() -> bool\n\
\n\
This method returns true if the mode used in the MCRYPT instance\n\
supports the iv parameter.\n\
";

static PyObject *
MCRYPT_has_iv(MCRYPTObject *self, PyObject *args)
{
	int rc;
	/* Stream mode is wrongly answering 1 here in
	 * some versions of mcrypt. */
	if (strcmp("stream", self->mode) == 0)
		return PyInt_FromLong(0);
	rc = mcrypt_enc_mode_has_iv(self->thread);
	if (catch_mcrypt_error(rc))
		return NULL;
	return PyInt_FromLong(rc);
}

static char MCRYPT_get_iv_size__doc__[] =
"get_iv_size() -> iv_size\n\
\n\
This method returns the iv size supported by the algorithm\n\
used in the MCRYPT instance.\n\
";

static PyObject *
MCRYPT_get_iv_size(MCRYPTObject *self, PyObject *args)
{
	int rc = mcrypt_enc_get_iv_size(self->thread);
	if (catch_mcrypt_error(rc))
		return NULL;
	return PyInt_FromLong(rc);
}

static char MCRYPT_is_block_algorithm__doc__[] =
"is_block_algorithm() -> bool\n\
\n\
Returns 1 if the algorithm is a block algorithm or 0 if it\n\
is a stream algorithm.\n\
";

static PyObject *
MCRYPT_is_block_algorithm(MCRYPTObject *self, PyObject *args)
{
	int rc = mcrypt_enc_is_block_algorithm(self->thread);
	if (catch_mcrypt_error(rc))
		return NULL;
	return PyInt_FromLong(rc);
}

static char MCRYPT_is_block_mode__doc__[] =
"is_block_mode() -> bool\n\
\n\
Returns 1 if the mode outputs blocks of bytes or 0 if it\n\
outputs bytes. (eg. 1 for cbc and ecb, and 0 for cfb and\n\
stream).\n\
";

static PyObject *
MCRYPT_is_block_mode(MCRYPTObject *self, PyObject *args)
{
	return PyInt_FromLong(self->block_mode);
}

static char MCRYPT_is_block_algorithm_mode__doc__[] =
"is_block_algorithm_mode() -> bool\n\
\n\
Returns 1 if the mode is for use with block algorithms,\n\
otherwise it returns 0. (eg. 0 for stream, and 1 for cbc,\n\
cfb, ofb).\n\
";

static PyObject *
MCRYPT_is_block_algorithm_mode(MCRYPTObject *self, PyObject *args)
{
	int rc = mcrypt_enc_is_block_algorithm_mode(self->thread);
	if (catch_mcrypt_error(rc))
		return NULL;
	return PyInt_FromLong(rc);
}

static PyMethodDef MCRYPT_methods[] = {
	{"init",		(PyCFunction)MCRYPT_init,
		METH_VARARGS|METH_KEYWORDS,	MCRYPT_init__doc__},
	{"reinit",		(PyCFunction)MCRYPT_reinit,
		METH_NOARGS,			MCRYPT_reinit__doc__},
	{"deinit",		(PyCFunction)MCRYPT_deinit,
		METH_NOARGS,			MCRYPT_deinit__doc__},
	{"encrypt",		(PyCFunction)MCRYPT_encrypt,
		METH_VARARGS|METH_KEYWORDS,	MCRYPT_encrypt__doc__},
	{"decrypt",		(PyCFunction)MCRYPT_decrypt,
		METH_VARARGS|METH_KEYWORDS,	MCRYPT_decrypt__doc__},
	{"encrypt_file",	(PyCFunction)MCRYPT_encrypt_file,
		METH_VARARGS|METH_KEYWORDS,	MCRYPT_encrypt_file__doc__},
	{"decrypt_file",	(PyCFunction)MCRYPT_decrypt_file,
		METH_VARARGS|METH_KEYWORDS,	MCRYPT_decrypt_file__doc__},
	{"get_block_size",	(PyCFunction)MCRYPT_get_block_size,
		METH_NOARGS,			MCRYPT_get_block_size__doc__},
	{"get_key_size",	(PyCFunction)MCRYPT_get_key_size,
		METH_NOARGS,			MCRYPT_get_key_size__doc__},
	{"get_key_sizes",	(PyCFunction)MCRYPT_get_key_sizes,
		METH_NOARGS,			MCRYPT_get_key_sizes__doc__},
	{"has_iv",		(PyCFunction)MCRYPT_has_iv,
		METH_NOARGS,			MCRYPT_has_iv__doc__},
	{"get_iv_size",		(PyCFunction)MCRYPT_get_iv_size,
		METH_NOARGS,			MCRYPT_get_iv_size__doc__},
	{"is_block_algorithm",	(PyCFunction)MCRYPT_is_block_algorithm,
		METH_NOARGS,		MCRYPT_is_block_algorithm__doc__},
	{"is_block_mode",	(PyCFunction)MCRYPT_is_block_mode,
		METH_NOARGS,		MCRYPT_is_block_mode__doc__},
	{"is_block_algorithm_mode", (PyCFunction)MCRYPT_is_block_algorithm_mode,
		METH_NOARGS,		MCRYPT_is_block_algorithm_mode__doc__},
	{NULL,		NULL}		/* sentinel */
};

static char MCRYPT__doc__[] =
"This is the main class. Its instances offer encryption and decryption\n\
functionality. MCRYPT is implmented as a newstyle class. It means you may\n\
subclass it in your python programs and extend its functionality. Don't\n\
forget to call its __init__ method if you do this.\n\
\n\
\n\
Constructor\n\
-----------\n\
\n\
MCRYPT(algorithm, mode [, algorithm_dir, mode_dir])\n\
\n\
The first parameter is a string containing the name of a known cryptography\n\
algorithm. The second parameter is a string containing the name of a known\n\
cryptography mode. The third and fourth parameters are used to select the\n\
directory where the mcrypt library will look for the respective modules.\n\
You usually won't have to set these, and if you have to, you may want to\n\
use the set_algorithm_dir() and set_mode_dir() functions provided in the\n\
mcrypt module, so you won't have to set these everytime you instantiate\n\
an MCRYPT object.\n\
\n\
\n\
Methods\n\
-------\n\
\n\
You may check the inline documentations of each of this methods for\n\
more information about them.\n\
\n\
init(key [, iv])\n\
reinit()\n\
deinit()\n\
encrypt(data [, fixlength=0])\n\
decrypt(data [, fixlength=0])\n\
encrypt_file(filein, fileout, [, fixlength=0, bufferblocks=1024])\n\
decrypt_file(filein, fileout, [, fixlength=0, bufferblocks=1024])\n\
get_block_size()\n\
get_key_size()\n\
get_key_sizes()\n\
get_iv_size()\n\
is_block_algorithm()\n\
is_block_mode()\n\
is_block_algorithm_mode()\n\
\n\
\n\
Attributes\n\
----------\n\
\n\
algorithm   - Selected algorithm.\n\
mode        - Selected mode.\n\
";

statichere PyTypeObject MCRYPT_Type = {
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"mcrypt.MCRYPT",	/*tp_name*/
	sizeof(MCRYPTObject),	/*tp_basicsize*/
	0,			/*tp_itemsize*/
	(destructor)MCRYPT_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	0,			/*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
        0,                      /*tp_call*/
        0,                      /*tp_str*/
        PyObject_GenericGetAttr,/*tp_getattro*/
        PyObject_GenericSetAttr,/*tp_setattro*/
        0,                      /*tp_as_buffer*/
        Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        MCRYPT__doc__,           /*tp_doc*/
        0,                      /*tp_traverse*/
        0,                      /*tp_clear*/
        0,                      /*tp_richcompare*/
        0,                      /*tp_weaklistoffset*/
        0,                      /*tp_iter*/
        0,                      /*tp_iternext*/
        MCRYPT_methods,          /*tp_methods*/
        MCRYPT_members,          /*tp_members*/
        0,                      /*tp_getset*/
        0,                      /*tp_base*/
        0,                      /*tp_dict*/
        0,                      /*tp_descr_get*/
        0,                      /*tp_descr_set*/
        0,                      /*tp_dictoffset*/
        (initproc)MCRYPT__init__,   /*tp_init*/
        PyType_GenericAlloc,    /*tp_alloc*/
        PyType_GenericNew,      /*tp_new*/
      	_PyObject_Del,       /*tp_free*/
        0,                      /*tp_is_gc*/
};
/* --------------------------------------------------------------------- */

/* List of functions defined in the module */

static int
get_dir_from_obj(PyObject *dirobj, char *default_dir, char **dir)
{
	if (dirobj == NULL) {
		*dir = default_dir;
	} else if (dirobj == Py_None) {
		*dir = NULL;
	} else if (PyString_Check(dirobj)) {
		*dir = PyString_AsString(dirobj);
	} else {
		PyErr_SetString(PyExc_TypeError,
				"directory must be None or a string");
		return 0;
	}
	return 1;
}

static char _mcrypt_set_algorithm_dir__doc__[] =
"set_algorithm_dir(algorithm_dir) -> None\n\
\n\
This handy function sets the default algorithm directory used by the\n\
MCRYPT constructor, and other functions. Modules will be searched in\n\
the given directory, besides the default ones.\n\
";

PyObject *
_mcrypt_set_algorithm_dir(PyObject *self, PyObject *adirobj)
{
	if (adirobj == Py_None) {
		free(algorithm_dir);
		algorithm_dir = NULL;
	} else if (PyString_Check(adirobj)) {
		free(algorithm_dir);
		algorithm_dir = strdup(PyString_AsString(adirobj));
		if (algorithm_dir == NULL) {
			PyErr_NoMemory();
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_TypeError,
				"algorithm_dir must be None or a string");
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static char _mcrypt_set_mode_dir__doc__[] =
"set_mode_dir(mode_dir) -> None\n\
\n\
This handy function sets the default mode directory used by the\n\
MCRYPT constructor, and other functions. Modules will be searched in\n\
the given directory, besides the default ones.\n\
";

PyObject *
_mcrypt_set_mode_dir(PyObject *self, PyObject *mdirobj)
{
	if (mdirobj == Py_None) {
		free(mode_dir);
		mode_dir = NULL;
	} else if (PyString_Check(mdirobj)) {
		free(mode_dir);
		mode_dir = strdup(PyString_AsString(mdirobj));
		if (mode_dir == NULL) {
			PyErr_NoMemory();
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_TypeError,
				"mode_dir must be None or a string");
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static char _mcrypt_list_algorithms__doc__[] =
"list_algorithms([algorithm_dir]) -> algorithm_list\n\
\n\
This function returns a list of algorithms found in the provided\n\
directory and in the default ones.\n\
\n\
You usually won't have to provide the directory, and if you have to,\n\
you may want to use the set_algorithm_dir() functions, so you won't\n\
have to set these everytime you call a function requiring this\n\
parameter.\n\
";

PyObject *
_mcrypt_list_algorithms(PyObject *self, PyObject *args)
{
	int size;
	char **algorithms;
	char *adir;
	PyObject *adirobj = NULL;
	PyObject *ret;
	int i;

	if (!PyArg_ParseTuple(args, "|O:list_algorithms", &adirobj))
		return NULL;

	if (!get_dir_from_obj(adirobj, algorithm_dir, &adir))
		return NULL;

	algorithms = mcrypt_list_algorithms(adir, &size);
	if (algorithms == NULL) {
		PyErr_SetString(MCRYPTError, "unknown mcrypt error");
		return NULL;
	}
	ret = PyList_New(size);
	if (ret != NULL)
		for (i = 0; i != size; i++) {
			PyObject *o = PyString_FromString(algorithms[i]);
			if (o == NULL) {
				PyObject_Del(ret);
				ret = NULL;
				break;
			}
			PyList_SetItem(ret, i, o);
		}
	mcrypt_free_p(algorithms, size);

	return ret;
}

static char _mcrypt_list_modes__doc__[] =
"list_modes([mode_dir]) -> mode_list\n\
\n\
This function returns a list of modes found in the provided directory\n\
and in the default ones.\n\
\n\
You usually won't have to provide the directory, and if you have to,\n\
you may want to use the set_mode_dir() functions, so you won't have to\n\
set these everytime you call a function requiring this parameter.\n\
";

PyObject *
_mcrypt_list_modes(PyObject *self, PyObject *args)
{
	int size;
	char **modes;
	char *mdir;
	PyObject *mdirobj = NULL;
	PyObject *ret;
	int i;

	if (!PyArg_ParseTuple(args, "|O:list_modes", &mdirobj))
		return NULL;

	if (!get_dir_from_obj(mdirobj, mode_dir, &mdir))
		return NULL;

	modes = mcrypt_list_modes(mdir, &size);
	if (modes == NULL) {
		PyErr_SetString(MCRYPTError, "unknown mcrypt error");
		return NULL;
	}
	ret = PyList_New(size);
	if (ret != NULL)
		for (i = 0; i != size; i++) {
			PyObject *o = PyString_FromString(modes[i]);
			if (o == NULL) {
				PyObject_Del(ret);
				ret = NULL;
				break;
			}
			PyList_SetItem(ret, i, o);
		}
	mcrypt_free_p(modes, size);

	return ret;
}

static char _mcrypt_is_block_algorithm__doc__[] =
"is_block_algorithm(algorithm [, algorithm_dir]) -> bool\n\
\n\
Returns 1 if the given algorithm is a block algorithm or 0 if it\n\
is a stream algorithm.\n\
\n\
You usually won't have to provide the directory, and if you have to,\n\
you may want to use the set_algorithm_dir() functions, so you won't\n\
have to set these everytime you call a function requiring this\n\
parameter.\n\
";

static PyObject *
_mcrypt_is_block_algorithm(PyObject *self, PyObject *args)
{
	PyObject *adirobj = NULL;
	char *algorithm, *adir;
	int ret;
	if (!PyArg_ParseTuple(args, "s|O:is_block_algorithm", &algorithm,
			      &adirobj))
		return NULL;
	
	if (!get_dir_from_obj(adirobj, algorithm_dir, &adir))
		return NULL;

	if (!check_algorithm(algorithm, adir))
		return NULL;

	ret = mcrypt_module_is_block_algorithm(algorithm, adir);
	if (catch_mcrypt_error(ret))
		return NULL;
	return PyInt_FromLong(ret);
}

static char _mcrypt_is_block_mode__doc__[] =
"is_block_mode(mode [, mode_dir]) -> bool\n\
\n\
Returns 1 if the mode outputs blocks of bytes or 0 if it outputs\n\
bytes. (eg. 1 for cbc and ecb, and 0 for cfb and stream).\n\
\n\
You usually won't have to provide the directory, and if you have to,\n\
you may want to use the set_mode_dir() functions, so you won't have to\n\
set these everytime you call a function requiring this parameter.\n\
";

static PyObject *
_mcrypt_is_block_mode(PyObject *self, PyObject *args)
{
	PyObject *mdirobj = NULL;
	char *mode, *mdir;
	int ret;
	if (!PyArg_ParseTuple(args, "s|O:is_block_mode", &mode, &mdirobj))
		return NULL;

	if (!get_dir_from_obj(mdirobj, mode_dir, &mdir))
		return NULL;

	if (!check_mode(mode, mdir))
		return NULL;

	ret = mcrypt_module_is_block_mode(mode, mdir);
	if (catch_mcrypt_error(ret))
		return NULL;
	return PyInt_FromLong(ret);
}

static char _mcrypt_is_block_algorithm_mode__doc__[] =
"is_block_algorithm_mode(algorithm [, algorithm_dir]) -> bool\n\
\n\
Returns 1 if the mode is for use with block algorithms, otherwise it\n\
returns 0. (eg. 0 for stream, and 1 for cbc, cfb, ofb).\n\
\n\
You usually won't have to provide the directory, and if you have to,\n\
you may want to use the set_algorithm_dir() functions, so you won't\n\
have to set these everytime you call a function requiring this\n\
parameter.\n\
";

static PyObject *
_mcrypt_is_block_algorithm_mode(PyObject *self, PyObject *args)
{
	PyObject *mdirobj = NULL;
	char *mode, *mdir;
	int ret;
	if (!PyArg_ParseTuple(args, "s|O:is_block_algorithm_mode", &mode,
			      &mdirobj))
		return NULL;

	if (!get_dir_from_obj(mdirobj, mode_dir, &mdir))
		return NULL;

	if (!check_mode(mode, mdir))
		return NULL;

	ret = mcrypt_module_is_block_algorithm_mode(mode, mdir);
	if (catch_mcrypt_error(ret))
		return NULL;
	return PyInt_FromLong(ret);
}

static char _mcrypt_get_block_size__doc__[] =
"get_block_size(algorithm [, algorithm_dir]) -> block_size\n\
\n\
Returns the block size of the given algorithm.\n\
\n\
You usually won't have to provide the directory, and if you have to,\n\
you may want to use the set_algorithm_dir() functions, so you won't\n\
have to set these everytime you call a function requiring this\n\
parameter.\n\
";

static PyObject *
_mcrypt_get_block_size(PyObject *self, PyObject *args)
{
	PyObject *adirobj = NULL;
	char *algorithm, *adir;
	int ret;
	if (!PyArg_ParseTuple(args, "s|O:get_block_size", &algorithm,
			      &adirobj))
		return NULL;

	if (!get_dir_from_obj(adirobj, algorithm_dir, &adir))
		return NULL;

	if (!check_algorithm(algorithm, adir))
		return NULL;

	ret = mcrypt_module_get_algo_block_size(algorithm, adir);
	if (catch_mcrypt_error(ret))
		return NULL;
	return PyInt_FromLong(ret);
}

static char _mcrypt_get_key_size__doc__[] =
"get_key_size(algorithm [, algorithm_dir]) -> key_size\n\
\n\
This function returns the maximum key size supported by the given\n\
algorithm. To know the acceptable key sizes, you must check the\n\
get_key_sizes() function.\n\
\n\
You usually won't have to provide the directory, and if you have to,\n\
you may want to use the set_algorithm_dir() functions, so you won't\n\
have to set these everytime you call a function requiring this\n\
parameter.\n\
";

static PyObject *
_mcrypt_get_key_size(PyObject *self, PyObject *args)
{
	PyObject *adirobj = NULL;
	char *algorithm, *adir;
	int ret;
	if (!PyArg_ParseTuple(args, "s|O:get_key_size", &algorithm,
			      &adirobj))
		return NULL;

	if (!get_dir_from_obj(adirobj, algorithm_dir, &adir))
		return NULL;

	if (!check_algorithm(algorithm, adir))
		return NULL;

	ret = mcrypt_module_get_algo_key_size(algorithm, adir);
	if (catch_mcrypt_error(ret))
		return NULL;
	return PyInt_FromLong(ret);
}

static char _mcrypt_get_key_sizes__doc__[] =
"get_key_sizes(algorithm [, algorithm_dir]) -> key_size_list\n\
\n\
This function returns a list of key sizes supported by the given\n\
algorithm. If this list is empty, any length between 1 and the\n\
maximum key size (returned by the get_key_size() function) may\n\
be used.\n\
\n\
You usually won't have to provide the directory, and if you have to,\n\
you may want to use the set_algorithm_dir() functions, so you won't\n\
have to set these everytime you call a function requiring this\n\
parameter.\n\
";

static PyObject *
_mcrypt_get_key_sizes(PyObject *self, PyObject *args)
{
	PyObject *adirobj = NULL;
	char *algorithm, *adir;
	int *key_sizes, size;
	PyObject *ret;
	
	if (!PyArg_ParseTuple(args, "s|O:get_key_sizes", &algorithm,
			      &adirobj))
		return NULL;

	if (!get_dir_from_obj(adirobj, algorithm_dir, &adir))
		return NULL;

	if (!check_algorithm(algorithm, adir))
		return NULL;

	key_sizes = mcrypt_module_get_algo_supported_key_sizes(algorithm,
							       adir, &size);
	ret = PyList_New(size);
	if (ret != NULL) {
		int i;
		for (i = 0; i != size; i++) {
			PyObject *o = PyInt_FromLong(key_sizes[i]);
			if (o == NULL) {
				PyObject_Del(ret);
				ret = NULL;
				break;
			}
			PyList_SetItem(ret, i, o);
		}
	}
	mcrypt_free(key_sizes);

	return ret;
}

static PyMethodDef mcrypt_methods[] = {
	{"set_algorithm_dir",		_mcrypt_set_algorithm_dir,
		METH_O,		_mcrypt_set_algorithm_dir__doc__},
	{"set_mode_dir",		_mcrypt_set_mode_dir,
		METH_O,		_mcrypt_set_mode_dir__doc__},
	{"list_algorithms",		_mcrypt_list_algorithms,
		METH_VARARGS,	_mcrypt_list_algorithms__doc__},
	{"list_modes",			_mcrypt_list_modes,
		METH_VARARGS,	_mcrypt_list_modes__doc__},
	{"is_block_algorithm",		_mcrypt_is_block_algorithm,
		METH_VARARGS,	_mcrypt_is_block_algorithm__doc__},
	{"is_block_mode",		_mcrypt_is_block_mode,
		METH_VARARGS,	_mcrypt_is_block_mode__doc__},
	{"is_block_algorithm_mode",	_mcrypt_is_block_algorithm_mode,
		METH_VARARGS,	_mcrypt_is_block_algorithm_mode__doc__},
	{"get_block_size",		_mcrypt_get_block_size,
		METH_VARARGS,	_mcrypt_get_block_size__doc__},
	{"get_key_size",		_mcrypt_get_key_size,
		METH_VARARGS,	_mcrypt_get_key_size__doc__},
	{"get_key_sizes",		_mcrypt_get_key_sizes,
		METH_VARARGS,	_mcrypt_get_key_sizes__doc__},
	{NULL,		NULL}		/* sentinel */
};


/* Locking functions, if we have threads enabled. */
#ifdef WITH_THREAD
static PyThread_type_lock mcrypt_lock = NULL;
static int mcrypt_lock_count = 0;

static void
mutex_lock(void)
{
	printf("Acquiring lock (count=%d)\n", mcrypt_lock_count);
	mcrypt_lock_count++;
	if (mcrypt_lock_count > 0) {
		Py_BEGIN_ALLOW_THREADS
		PyThread_acquire_lock(mcrypt_lock, 1);
		Py_END_ALLOW_THREADS
	}
	printf("Lock acquired (count=%d)\n", mcrypt_lock_count);
}

static void
mutex_unlock(void)
{
	printf("Releasing lock (count=%d)\n", mcrypt_lock_count);
	mcrypt_lock_count--;
	PyThread_release_lock(mcrypt_lock);
	printf("Lock released (count=%d)\n", mcrypt_lock_count);
}
#endif /* WITH_THREAD */

static char mcrypt__doc__[] =
"The mcrypt library provides an easy to use interface for several\n\
algorithms and modes of cryptography. The algorithms SERPENT, RIJNDAEL,\n\
3DES, GOST, SAFER+, CAST-256, RC2, XTEA, 3WAY, TWOFISH, BLOWFISH,\n\
ARCFOUR, and WAKE are some of the supported by the library.\n\
\n\
This module exports functionality provided by the mcrypt library to\n\
python programs.\n\
\n\
\n\
Classes\n\
-------\n\
\n\
Instances of this class, or subclasses of it, may be used to encyrpt\n\
and decrypt strings and files. This is a newstyle class, and thys may be\n\
subclassed by python classes.\n\
\n\
MCRYPT(algorithm, mode [, algorithm_dir, mode_dir])\n\
\n\
\n\
Functions\n\
---------\n\
\n\
These functions are used to extract information about algorithms and\n\
modes, without creating an MCRYPT instance. Instances of MCRYPT may\n\
access most of this data about the selected algorithm and mode trough\n\
its methods.\n\
\n\
set_algorithm_dir(algorithm_dir)\n\
set_mode_dir(mode_dir)\n\
list_algorithms([algorithm_dir])\n\
list_modes([mode_dir])\n\
is_block_algorithm(algorithm [, algorithm_dir])\n\
is_block_mode(mode [, mode_dir])\n\
is_block_algorithm_mode(mode [, mode_dir])\n\
get_block_size(algorithm [, algorithm_dir])\n\
get_key_size(algorithm [, algorithm_dir])\n\
get_key_sizes(algorithm [, algorithm_dir])\n\
\n\
\n\
Constants\n\
---------\n\
\n\
MCRYPT_*\n\
";

DL_EXPORT(void)
initmcrypt(void)
{
	PyObject *m;

	MCRYPT_Type.ob_type = &PyType_Type;

	m = Py_InitModule3("mcrypt", mcrypt_methods, mcrypt__doc__);

	PyModule_AddObject(m, "__author__", PyString_FromString(__author__));
	PyModule_AddObject(m, "__version__", PyString_FromString(VERSION));

	Py_INCREF(&MCRYPT_Type);
	PyModule_AddObject(m, "MCRYPT", (PyObject *)&MCRYPT_Type);

	MCRYPTError = PyErr_NewException("mcrypt.MCRYPTError", NULL, NULL);
	PyModule_AddObject(m, "MCRYPTError", MCRYPTError);

#ifdef WITH_THREAD
	mcrypt_lock = PyThread_allocate_lock();
	mcrypt_mutex_register(mutex_lock, mutex_unlock, NULL, NULL);
#endif

#define INSSTR(a,b) PyModule_AddStringConstant(m, #a, b)

/* We're not defining this on purpose. Some of those algorithms may
 * not be available, and others not listed here may be. Some definitions
 * are also known to be missing (at least at this time). Another reason
 * is that "des" is easier to use than MCRYPT_DES. */

#if 0
	/* Algorithms */
	INSSTR(MCRYPT_BLOWFISH);
	INSSTR(MCRYPT_DES);
	INSSTR(MCRYPT_3DES);
	INSSTR(MCRYPT_3WAY);
	INSSTR(MCRYPT_GOST);
	INSSTR(MCRYPT_SAFER_SK64);
	INSSTR(MCRYPT_SAFER_SK128);
	INSSTR(MCRYPT_CAST_128);
	INSSTR(MCRYPT_XTEA);
	INSSTR(MCRYPT_RC2);
	INSSTR(MCRYPT_TWOFISH);
	INSSTR(MCRYPT_CAST_256);
	INSSTR(MCRYPT_SAFERPLUS);
	INSSTR(MCRYPT_LOKI97);
	INSSTR(MCRYPT_SERPENT);
	INSSTR(MCRYPT_RIJNDAEL_128);
	INSSTR(MCRYPT_RIJNDAEL_192);
	INSSTR(MCRYPT_RIJNDAEL_256);
	INSSTR(MCRYPT_ENIGMA);
	INSSTR(MCRYPT_ARCFOUR);
	INSSTR(MCRYPT_WAKE);

        /* Modes */
	INSSTR(MCRYPT_CBC);
	INSSTR(MCRYPT_ECB);
	INSSTR(MCRYPT_CFB);
	INSSTR(MCRYPT_OFB);
	INSSTR(MCRYPT_nOFB);
	INSSTR(MCRYPT_nCFB); /* This one is missing in mcrypt.h. */
	INSSTR(MCRYPT_STREAM);
#endif

}
