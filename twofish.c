#include <Python.h>
#include "twofish.h"

void py_twofish_key_destructor(PyObject *capsule)
{
    void *ptr = PyCapsule_GetPointer(capsule, "key");
    if (ptr != NULL)
    {
        free(ptr);
    }
}

static PyObject *py_twofish_prepare_key(PyObject *self, PyObject *args)
{
    PyObject *key;

    if (!PyArg_ParseTuple(args, "O", &key))
    {
        return NULL;
    }

    if (!PyBytes_Check(key))
    {
        PyErr_SetString(PyExc_TypeError, "key is not a bytes object");
        return NULL;
    }

    unsigned char *key_buf = (unsigned char *)PyBytes_AsString(key);
    if (key_buf == NULL)
    {
        PyErr_SetString(PyExc_TypeError, "key is not a bytes object");
        return NULL;
    }

    int keyLen = (int)PyBytes_Size(key);
    if (keyLen < 0 || keyLen > 32)
    {
        PyErr_SetString(PyExc_TypeError, "invalid key length");
        return NULL;
    }

    Twofish_key *xKey = (Twofish_key *)malloc(sizeof(Twofish_key));
    Twofish_prepare_key(key_buf, keyLen, xKey);

    PyObject *keyObj = PyCapsule_New((void *)xKey, "key", py_twofish_key_destructor);
    if (keyObj == NULL)
    {
        free(xKey);
    }

    return keyObj;
}

static PyObject *py_twofish_encrypt(PyObject *self, PyObject *args)
{
    PyObject *keyObj, *plaintextBytes;
    unsigned char ciphertext[16];

    if (!PyArg_ParseTuple(args, "OO", &keyObj, &plaintextBytes))
    {
        return NULL;
    }

    void *xkey = PyCapsule_GetPointer(keyObj, "key");
    if (xkey == NULL)
    {
        PyErr_SetString(PyExc_TypeError, "invalid key");
        return NULL;
    }

    if (!PyBytes_Check(plaintextBytes))
    {
        PyErr_SetString(PyExc_TypeError, "plaintext is not a bytes object");
        return NULL;
    }

    unsigned char *plaintextBuf = (unsigned char *)PyBytes_AsString(plaintextBytes);
    if (plaintextBuf == NULL)
    {
        PyErr_SetString(PyExc_TypeError, "plaintext is not a bytes object");
        return NULL;
    }

    int keyLen = (int)PyBytes_Size(plaintextBytes);
    if (keyLen != 16)
    {
        PyErr_SetString(PyExc_TypeError, "invalid plaintext length");
        return NULL;
    }

    Twofish_encrypt(xkey, plaintextBuf, ciphertext);
    return PyBytes_FromStringAndSize((char *)ciphertext, 16);
}

static PyObject *py_twofish_decrypt(PyObject *self, PyObject *args)
{
    PyObject *keyObj, *ciphertextBytes;
    unsigned char plaintext[16];

    if (!PyArg_ParseTuple(args, "OO", &keyObj, &ciphertextBytes))
    {
        return NULL;
    }

    void *xkey = PyCapsule_GetPointer(keyObj, "key");
    if (xkey == NULL)
    {
        PyErr_SetString(PyExc_TypeError, "invalid key");
        return NULL;
    }

    if (!PyBytes_Check(ciphertextBytes))
    {
        PyErr_SetString(PyExc_TypeError, "ciphertext is not a bytes object");
        return NULL;
    }

    unsigned char *ciphertextBuf = (unsigned char *)PyBytes_AsString(ciphertextBytes);
    if (ciphertextBuf == NULL)
    {
        PyErr_SetString(PyExc_TypeError, "ciphertext is not a bytes object");
        return NULL;
    }

    int keyLen = (int)PyBytes_Size(ciphertextBytes);
    if (keyLen != 16)
    {
        PyErr_SetString(PyExc_TypeError, "invalid ciphertext length");
        return NULL;
    }

    Twofish_decrypt(xkey, ciphertextBuf, plaintext);
    return PyBytes_FromStringAndSize((char *)plaintext, 16);
}

static PyMethodDef TwofishMethods[] = {
    {"prepare_key", py_twofish_prepare_key, METH_VARARGS, "Prepare the Twofish key"},
    {"encrypt", py_twofish_encrypt, METH_VARARGS, "Encrypt a block with Twofish"},
    {"decrypt", py_twofish_decrypt, METH_VARARGS, "Decrypt a block with Twofish"},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "_twofish",
    NULL,
    -1,
    TwofishMethods};

PyMODINIT_FUNC PyInit__twofish(void)
{
    Twofish_initialise();
    return PyModule_Create(&module);
}
