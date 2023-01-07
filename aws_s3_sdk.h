/**************************************************************************
 * Copyright (C) 2022-2023  Junlon2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 **************************************************************************/
#ifndef __AWS_S3_SDK_H__
#define __AWS_S3_SDK_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief push data to aws s3 bucket
 * 
 * @param data userdata
 * @param len  userdata length
 * @param object_name the object name of this data push to s3
 * @param id user id
 * @param secret user secret
 * @param token access token
 * @param service service name, set as "s3" for aws s3 service
 * @param region s3 region
 * @param bucket_name s3 bucket name
 * @return int 0 for success, otherwise failed
 */
int aws_s3_push(const char *data, int len, const char *object_name,
                const char *id, const char *secret, const char *token,
                const char *service, const char *region, const char *bucket_name);

#ifdef __cplusplus
}
#endif
#endif  /* __AWS_S3_SDK_H__ */
