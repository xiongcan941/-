#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <aes_ta.h>

#define AES128_KEY_BIT_SIZE		128
#define AES128_KEY_BYTE_SIZE		(AES128_KEY_BIT_SIZE / 8)

//创建人脸数据文件
static TEE_Result create_face_data_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,//用户ID由CA指定
				TEE_PARAM_TYPE_MEMREF_INPUT,//人脸数据
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char* obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;
	uint32_t obj_data_flag;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	//复制CA传递的Uid以及人脸数据
	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	data_sz = params[1].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(data, params[1].memref.buffer, data_sz);

	obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |		/* we can later read the oject */
			TEE_DATA_FLAG_ACCESS_WRITE |		/* we can later write into the object */
			TEE_DATA_FLAG_ACCESS_WRITE_META |	/* we can later destroy or rename the object */
			TEE_DATA_FLAG_OVERWRITE;		/* destroy existing object of same ID */

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					&obj_id, obj_id_sz,
					obj_data_flag,
					TEE_HANDLE_NULL,
					NULL, 0,		/* we may not fill it right now */
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
		TEE_Free(data);
		return res;
	}

	res = TEE_WriteObjectData(object, data, data_sz);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_WriteObjectData failed 0x%08x", res);
		TEE_CloseAndDeletePersistentObject1(object);
	} else {
		TEE_CloseObject(object);
	}
	TEE_Free(obj_id);
	TEE_Free(tmp);
	return res;
}

//删除人脸数据文件
static TEE_Result delete_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_VALUE_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
	char* obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;
	char *read_data;
	size_t read_data_sz;
	TEE_ObjectEnumHandle iter_enum = NULL;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = 255;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	data_sz = params[0].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

	read_data_sz = params[0].memref.size;
	read_data = TEE_Malloc(read_data_sz, 0);
	if (!read_data)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(data, params[0].memref.buffer, data_sz);

	res = TEE_AllocatePersistentObjectEnumerator(&iter_enum);
	if (res != TEE_SUCCESS) {
		printf("Fail: iter alloc\n");
		goto err;
	}

	res = TEE_StartPersistentObjectEnumerator(iter_enum, TEE_STORAGE_PRIVATE);
	if (res != TEE_SUCCESS) {
		printf("Fail: iter start\n");
		goto err;
	}

	for(;;) {
		res = TEE_GetNextPersistentObject(iter_enum, &object_info, &obj_id, &obj_id_sz);
		if (res == TEE_SUCCESS) {
			/*  */
			res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_SHARE_READ,
					&object);
			if (res != TEE_SUCCESS) {
				EMSG("Log on Failed, Failed to open persistent object, res=0x%08x", res);
				TEE_Free(data);
				return res;
			}

			res = TEE_GetObjectInfo1(object, &object_info);
			if (res != TEE_SUCCESS) {
				EMSG("Failed to create persistent object, res=0x%08x", res);
				goto exit;
			}

			res = TEE_ReadObjectData(object,read_data, object_info.dataSize,
				 &read_bytes);
			if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
				EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
				res, read_bytes, object_info.dataSize);
				goto exit;
			}
			else
			{
				//人脸识别函数位置，data与read_data进行比对
				//不成功，继续

				//成功，返回并退出循环
				//TEE_MemMove(params[1].memref.buffer, obj_id, obj_id_sz);
				//params[1].memref.size = obj_id_sz;
				//TEE_CloseAndDeletePersistentObject1(object);
				float * now = (float*) read_data;
				int i = 0 ;
				int face_size = read_bytes / 4;
				for(i = 0 ; i < face_size ; i++){
					printf("%f\n",now[i]);
				}
				//break;//退出循环
			}
		}else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;
		} else {
			printf("Fail: get next\n");
			goto exit;
		}
	}
exit:
	TEE_CloseObject(object);
	TEE_Free(data);
	return res;
}

//用户登录
static TEE_Result login(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,//人脸数据
				TEE_PARAM_TYPE_VALUE_OUTPUT,//返回登录的Uid
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
	char* obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;
	float *read_data;
	size_t read_data_sz;
	TEE_ObjectEnumHandle iter_enum = NULL;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

    obj_id_sz = 255;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	data_sz = params[0].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;
	
	read_data_sz = params[0].memref.size;
	read_data = TEE_Malloc(read_data_sz, 0);
	if (!read_data)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(data, params[0].memref.buffer, data_sz);

	res = TEE_AllocatePersistentObjectEnumerator(&iter_enum);
	if (res != TEE_SUCCESS) {
		printf("Fail: iter alloc\n");
		goto err;
	}

	res = TEE_StartPersistentObjectEnumerator(iter_enum, TEE_STORAGE_PRIVATE);
	if (res != TEE_SUCCESS) {
		printf("Fail: iter start\n");
		goto err;
	}

	for(;;) {
		res = TEE_GetNextPersistentObject(iter_enum, &object_info, &obj_id, &obj_id_sz);
		if (res == TEE_SUCCESS) {
			/*  */
			res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_SHARE_READ,
					&object);
			if (res != TEE_SUCCESS) {
				EMSG("Log on Failed, Failed to open persistent object, res=0x%08x", res);
				TEE_Free(obj_id);
				TEE_Free(data);
				TEE_Free(read_data);
				return res;
			}

			res = TEE_GetObjectInfo1(object, &object_info);
			if (res != TEE_SUCCESS) {
				EMSG("Failed to create persistent object, res=0x%08x", res);
				goto exit;
			}

			res = TEE_ReadObjectData(object, data, object_info.dataSize,
				 &read_bytes);
			if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
				EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
				res, read_bytes, object_info.dataSize);
				goto exit;
			}
			else{
				//人脸识别，成功则退出循环
				//不成功，继续

				//成功，返回并退出循环
				params[1].value = obj_id;
				break;
			}
		}else if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
			break;
		} else {
			printf("Fail: get next\n");
			goto exit;
		}
	}

exit:
	TEE_CloseObject(object);
	TEE_Free(obj_id);
	TEE_Free(data);
	return res;
}

//加密用户数据
static TEE_Result encode(uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	uint32_t algo;			/* AES加密方式 */
	uint32_t mode;			/* 加密或者解密 */
	uint32_t key_size;		/* AES key size in byte */
	TEE_OperationHandle op_handle;	/* AES 加密配置结构体handle */
	TEE_ObjectHandle key_handle;	/* 临时结构体 to load the key */
	TEE_Attribute attr;
	TEE_Result res;
	char *key;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	algo = TEE_ALG_AES_CTR;
	key_size = AES128_KEY_BYTE_SIZE;
	mode = TA_AES_MODE_ENCODE;

	res = TEE_AllocateOperation(&op_handle,
				    algo,
				    mode,
				    key_size * 8);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		op_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
					  key_size * 8,
					  &key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		key_handle = TEE_HANDLE_NULL;
		goto err;
	}

	key = TEE_Malloc(key_size, 0);
	if (!key) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	key[0] = 'y';
	key[1] = 'W';
	key[2] = 'A';
	key[3] = 'r';KEY[4] = 'r';KEY[5] = 'r';KEY[6] = 'r';KEY[7] = 'r';KEY[8] = 'r';KEY[9] = 'r';
	KEY[10] = 'r';KEY[11] = 'r';KEY[12] = 'r';KEY[13] = 'r';KEY[14] = 'r';KEY[15] = 'r';

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_size);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		goto err;
	}

	res = TEE_SetOperationKey(op_handle, key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		goto err;
	}

	if (op_handle == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;
	
	size_t iv_sz = 16;
	char iv[16] = {'0'};
	TEE_CipherInit(op_handle, &iv, iv_sz);
	return TEE_CipherUpdate(op_handle,
				params[0].memref.buffer, params[0].memref.size,
				params[1].memref.buffer, &params[1].memref.size);
}

//解密数据
static TEE_Result decode(uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	uint32_t algo;			/* AES加密方式 */
	uint32_t mode;			/* 加密或者解密 */
	uint32_t key_size;		/* AES key size in byte */
	TEE_OperationHandle op_handle;	/* AES 加密配置结构体handle */
	TEE_ObjectHandle key_handle;	/* 临时结构体 to load the key */
	TEE_Attribute attr;
	TEE_Result res;
	char *key;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	algo = TEE_ALG_AES_CTR;
	key_size = AES128_KEY_BYTE_SIZE;
	mode = TA_AES_MODE_DECODE;

	res = TEE_AllocateOperation(&op_handle,
				    algo,
				    mode,
				    key_size * 8);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		op_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
					  key_size * 8,
					  &key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		key_handle = TEE_HANDLE_NULL;
		goto err;
	}

	key = TEE_Malloc(key_size, 0);
	if (!key) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	key[0] = 'y';
	key[1] = 'W';
	key[2] = 'A';
	key[3] = 'r';KEY[4] = 'r';KEY[5] = 'r';KEY[6] = 'r';KEY[7] = 'r';KEY[8] = 'r';KEY[9] = 'r';
	KEY[10] = 'r';KEY[11] = 'r';KEY[12] = 'r';KEY[13] = 'r';KEY[14] = 'r';KEY[15] = 'r';

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_size);

	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		goto err;
	}

	res = TEE_SetOperationKey(op_handle, key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		goto err;
	}

	if (op_handle == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;
	
	size_t iv_sz = 16;
	char iv[16] = {'0'};
	TEE_CipherInit(op_handle, &iv, iv_sz);
	return TEE_CipherUpdate(op_handle,
				params[0].memref.buffer, params[0].memref.size,
				params[1].memref.buffer, &params[1].memref.size);
}

TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __unused **session)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
					uint32_t cmd,
					uint32_t param_types,
					TEE_Param params[4])
{
	switch (cmd) {
	case TA_CMD_ENCODE:
		return encode(param_types, params);
	case TA_CMD_DECODE:
		return decode(param_types, params);
	case TA_CMD_DELETE_DATA:
		return decode(param_types, params);
	case TA_CMD_REGISTER:
		return create_face_data_object(param_types, params);
	case TA_CMD_LOGIN:
		return login(param_types, params);
	case TA_CMD_DELETE_USER:
		return delete_object(param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
