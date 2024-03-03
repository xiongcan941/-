#include <err.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include "tee_client_api.h"

/* For the UUID (found in the TA's h-file(s)) */
#include "ta.h"

void openSession(TEEC_Result * res, TEEC_Context * ctx, TEEC_Session * sess, TEEC_UUID * uuid){
    uint32_t err_origin;

	*res = TEEC_InitializeContext(NULL, ctx);
	if (*res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", *res);

    /*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	*res = TEEC_OpenSession(ctx, sess, uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (*res != TEEC_SUCCESS){
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",*res, err_origin);
	}
}

//	用户注册，注册成功返回uid
const char * registerUser(const float * userFeature, const int featureLen, const char * uid){
	return "success for registerUser";
	// char uid[255];
	char filename[255];
    uint32_t err_origin;
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_UUID;
	int fd = -1;

	openSession(&res, &ctx, &sess, &uuid);

    //  调用ta接口，将从轻设备收到的数据发送到ta中，返回加密成功的数据

	//	arg1是用户人脸数据，arg2用来接收返回的UserInfo
	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_INPUT, userFeature, featureLen);

	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void*)userFeature;
	op.params[0].tmpref.size = featureLen;
	op.params[1].tmpref.buffer = uid;
	op.params[1].tmpref.size = 255;

	// printf("Invoking TA to increment %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_CMD_REGISTER, &op, &err_origin);

    TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

    if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
        return RESULT_FAIL;
    }

	// 创建一个文件，文件名为uid
	DIR* dirp = opendir("userInfo");
    if (!dirp) {
        perror("opendir");
        return RESULT_FAIL;
    }

    struct dirent* dp;
    while ((dp = readdir(dirp)) != NULL && !strcmp(dp->d_name, uid)) {}

	if (dp != NULL){
		return RESULT_FAIL;
	}

    closedir(dirp);

	snprintf(filename, sizeof(filename), "userInfo/%s", uid);

	fd = open(filename, O_CREAT);
    if (fd == -1) {
        perror("open");
        return RESULT_FAIL;
    }

    close(fd);

	if (strlen(uid) != 0){
		return uid;
	}

	return RESULT_FAIL;
}

//	向ta发送人脸特征，ta进行对比，如果对比成功返回uid，表示登录成功，否则返回空字符串
const char * loginUser(const float * userFeature, const int featureLen){
	return "success for loginUser";

	char uid[255] = "";
    uint32_t err_origin;
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_UUID;

	openSession(&res, &ctx, &sess, &uuid);

    //  调用ta接口，将从轻设备收到的数据发送到ta中，返回加密成功的数据
	//	arg1是用户人脸数据，arg2用来接收返回的UserInfo
	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_INPUT, userFeature, featureLen);
	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_OUTPUT, uid, sizeof(uid));
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void*)userFeature;
	op.params[0].tmpref.size = featureLen;
	op.params[1].tmpref.buffer = uid;
	op.params[1].tmpref.size = 255;

	// printf("Invoking TA to increment %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_CMD_LOGIN, &op, &err_origin);

    TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

    if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
        return RESULT_FAIL;
    }

	if (strlen(uid) == 0){
		return RESULT_FAIL;
	}

    return RESULT_SUCCESS;    
}

//	传入用户信息，进行加密，并存储
int fillInUserInfo(const char * userInfo, const char * uid){
	return 66666666;
	char encryptUserInfo[255];
	char encryptUid[255];
    uint32_t err_origin;
	int fd = -1;
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_UUID;

	openSession(&res, &ctx, &sess, &uuid);

    //  调用ta接口，将从轻设备收到的数据发送到ta中，返回加密成功的数据
	//	arg1是用户人脸数据，arg2用来接收返回的UserInfo
	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_INPUT, userInfo, sizeof(userInfo));
	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_INPUT, uid, sizeof(uid));
	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_OUTPUT, encryptUserInfo, sizeof(encryptUserInfo));
	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_OUTPUT, encryptUid, sizeof(encryptUid));

	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = (void*)userInfo;
	op.params[0].tmpref.size = strlen(userInfo);
	op.params[1].tmpref.buffer = (void*)uid;
	op.params[1].tmpref.size = strlen(userInfo);
	op.params[2].tmpref.buffer = (void*)encryptUserInfo;
	op.params[2].tmpref.size = 255;
	op.params[3].tmpref.buffer = (void*)encryptUid;
	op.params[3].tmpref.size = 255;

	/*
	 * TODO 更换接口
	 */
	printf("Invoking TA to increment %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_CMD_ENCODE, &op, &err_origin);

    TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

    if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
        return atoi(RESULT_FAIL);
    }

	//	将返回的数据进行存储，encryptUid为文件名，将encryptUserInfo存入其中
	DIR* dirp = opendir("userInfo");
    if (!dirp) {
        perror("opendir");
        return atoi(RESULT_FAIL);
    }

    struct dirent* dp;
    while ((dp = readdir(dirp)) != NULL) {
		if (!strcmp(dp->d_name, encryptUid)){
			fd = open(dp->d_name, O_RDWR);
            if (fd == -1) {
                perror("open");
                continue;
            }

            lseek(fd, 0, SEEK_SET); // Seek to the beginning of the file
            write(fd, encryptUserInfo, strlen(encryptUserInfo)); // Write new content to the file

            close(fd); // Close the file

			break;
		}
	}

    return atoi(RESULT_SUCCESS);    
}

// 查询用户，需要传入uid作为查询条件
const char * searchUser(const char * uid){
	return "success for searchUser";

	char encryptUid[255];
    uint32_t err_origin;
	char buffer[255];
	ssize_t bytes_read;
	char encryptUserInfo[255]; // 创建一个足够大的字符串变量
	char decryptUserInfo[255];
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_UUID;
	struct dirent* dp;
	int fd = -1;

	openSession(&res, &ctx, &sess, &uuid);

	//	将uid发送到ta中进行加密，接收返回值
	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_INPUT, uid, sizeof(uid));
    // TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_OUTPUT, encryptUid, sizeof(encryptUid));

	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void*)uid;
	op.params[0].tmpref.size = strlen(uid);
	op.params[1].tmpref.buffer = (void*)encryptUid;
	op.params[1].tmpref.size = 255;

	/*
	 * TODO 更换接口
	 */
	// printf("Invoking TA to increment %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_CMD_ENCODE, &op, &err_origin);

	//	读取文件列表，对文件名进行匹配，如果有匹配值则读取文件数据
	//	将返回的数据进行存储，encryptUid为文件名，将encryptUserInfo存入其中
	DIR* dirp = opendir("userInfo");
    if (!dirp) {
        perror("opendir");
        return RESULT_FAIL;
    }

    while ((dp = readdir(dirp)) != NULL) {
		if (!strcmp(dp->d_name, encryptUid)){
			fd = open(dp->d_name, O_RDWR);
            if (fd == -1) {
                perror("open");
                continue;
            }

			while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
				strncat(encryptUserInfo, buffer, bytes_read); // 追加数据到字符串中
			}

            close(fd); // Close the file
			break;
		}
	}

	//	将文件中读取到的数据发送到ta中，进行解密

	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_INPUT, uid, sizeof(encryptUserInfo));
    // TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_OUTPUT, decryptUserInfo, sizeof(decryptUserInfo));

	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void*)encryptUserInfo;
	op.params[0].tmpref.size = 255;
	op.params[1].tmpref.buffer = (void*)decryptUserInfo;
	op.params[1].tmpref.size = 255;

	/*
	 * TODO 更换接口
	 */
	printf("Invoking TA to increment %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_CMD_DECODE, &op, &err_origin);


    TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

    if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
        return RESULT_FAIL;
    }

    return decryptUserInfo;
}

//	删除指定的用户
int deleteUserForFeature(const float * userFeature, const int featureLen){
	return 88888888;

	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_UUID;
	char encryptUid[255];
    uint32_t err_origin;
	struct dirent* dp;


	openSession(&res, &ctx, &sess, &uuid);

    //  将userFeature发送到ta中，接收ta中返回的uid
	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_INPUT, userFeature, sizeof(userFeature));
	// TEE_SetOperationParameterValues(op, TEE_PARAM_TYPE_VALUE_OUTPUT, encryptUid, sizeof(encryptUid));
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void*)userFeature;
	op.params[0].tmpref.size = featureLen;
	op.params[1].tmpref.buffer = (void*)encryptUid;
	op.params[1].tmpref.size = 255;

	/*
	 * TODO 更换接口
	 */
	printf("Invoking TA to increment %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_CMD_DELETE_USER, &op, &err_origin);

    TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

    if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
        return atoi(RESULT_FAIL);
    }

	//	匹配文件名，将uid对应的文件删除
	//	匹配文件名，将对应的文件删除
	DIR* dirp = opendir("userInfo"); // 打开当前目录
    if (!dirp) {
        perror("opendir");
        exit(1);
    }

    while ((dp = readdir(dirp)) != NULL) {
        if (strcmp(dp->d_name, encryptUid) == 0) {
            remove(dp->d_name); // 删除文件
            printf("Deleted file: %s\n", dp->d_name);
        }
    }

    closedir(dirp);

    return atoi(RESULT_SUCCESS);
}

int main(void)
{
	float a[5] = {1.0,2.0,3.0,4.0,5.0};
	registerUser(a,5);
	return 0;
}
