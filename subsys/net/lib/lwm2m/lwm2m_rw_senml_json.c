/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_MODULE_NAME net_lwm2m_senml_json
#define LOG_LEVEL CONFIG_LWM2M_LOG_LEVEL

#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <sys/base64.h>

#include "lwm2m_object.h"
#include "lwm2m_rw_senml_json.h"
#include "lwm2m_rw_plain_text.h"
#include "lwm2m_engine.h"
#include "lwm2m_util.h"

#define T_OBJECT_BEGIN BIT(0)
#define T_OBJECT_END BIT(1)
#define T_STRING_BEGIN BIT(2)
#define T_STRING_END BIT(3)
#define T_VALUE BIT(4)

#define SENML_JSON_BASE_NAME_ATTRIBUTE 0
#define SENML_JSON_BASE_TIME_ATTRIBUTE 1
#define SENML_JSON_NAME_ATTRIBUTE 2
#define SENML_JSON_TIME_ATTRIBUTE 3
#define SENML_JSON_FLOAT_VALUE_ATTRIBUTE 4
#define SENML_JSON_BOOLEAN_VALUE_ATTRIBUTE 5
#define SENML_JSON_OBJ_LINK_VALUE_ATTRIBUTE 6
#define SENML_JSON_OPAQUE_VALUE_ATTRIBUTE 7
#define SENML_JSON_STRING_VALUE_ATTRIBUTE 8
#define SENML_JSON_STRING_BLOCK_DATA 9
#define SENML_JSON_UNKNOWN_ATTRIBUTE 255

#define SEPARATOR(f) ((f & WRITER_OUTPUT_VALUE) ? "," : "")

#define TOKEN_BUF_LEN 64

struct json_out_formatter_data {
	/* flags */
	uint8_t writer_flags;

	/* base name */
	struct lwm2m_obj_path base_name;
	/* Add Base name */
	bool base_name_used;
	bool add_base_name_to_start;
};

struct json_in_formatter_data {
	/* name info */
	uint16_t name_offset;
	uint16_t name_len;

	/* value info */
	uint16_t value_offset;
	/* Value length */
	uint16_t value_len;

	/* state */
	uint16_t offset;

	/* flags */
	uint8_t json_flags;
};

/* some temporary buffer space for format conversions */
static char json_buffer[TOKEN_BUF_LEN];

static int parse_path(const uint8_t *buf, uint16_t buflen, struct lwm2m_obj_path *path);

static void json_add_char(struct lwm2m_input_context *in, struct json_in_formatter_data *fd)
{
	if ((fd->json_flags & T_VALUE) ||
	    ((fd->json_flags & T_STRING_BEGIN) && !(fd->json_flags & T_STRING_END))) {
		if (fd->json_flags & T_VALUE) {
			fd->value_len++;
			if (fd->value_len == 1U) {
				fd->value_offset = fd->offset;
			}
		} else {
			fd->name_len++;
			if (fd->name_len == 1U) {
				fd->name_offset = fd->offset;
			}
		}
	}
}

static struct lwm2m_senml_json_context *seml_json_context_get(struct lwm2m_block_context *block_ctx)
{
	if (block_ctx) {
		return &block_ctx->senml_json_ctx;
	}

	return NULL;
}

static int json_atribute_decode(struct lwm2m_input_context *in, struct json_in_formatter_data *fd)
{
	uint8_t attrbute_name[3];

	if (fd->name_len == 0 || fd->name_len > 3) {
		if (fd->name_len == 0 && in->block_ctx && (fd->json_flags & T_VALUE) &&
		    (fd->json_flags & T_STRING_END)) {
			return SENML_JSON_STRING_BLOCK_DATA;
		}
		return SENML_JSON_UNKNOWN_ATTRIBUTE;
	}

	if (buf_read(attrbute_name, fd->name_len, CPKT_BUF_READ(in->in_cpkt), &fd->name_offset) <
	    0) {
		LOG_ERR("Error parsing attribute name!");
		return SENML_JSON_UNKNOWN_ATTRIBUTE;
	}

	if (fd->name_len == 1) {
		if (attrbute_name[0] == 'n') {
			return SENML_JSON_NAME_ATTRIBUTE;
		} else if (attrbute_name[0] == 't') {
			return SENML_JSON_TIME_ATTRIBUTE;
		} else if (attrbute_name[0] == 'v') {
			return SENML_JSON_FLOAT_VALUE_ATTRIBUTE;
		}

	} else if (fd->name_len == 2) {
		if (attrbute_name[0] == 'b') {
			if (attrbute_name[1] == 'n') {
				return SENML_JSON_BASE_NAME_ATTRIBUTE;
			} else if (attrbute_name[1] == 't') {
				return SENML_JSON_BASE_TIME_ATTRIBUTE;
			}
		} else if (attrbute_name[0] == 'v') {
			if (attrbute_name[1] == 'b') {
				return SENML_JSON_BOOLEAN_VALUE_ATTRIBUTE;
			} else if (attrbute_name[1] == 'd') {
				return SENML_JSON_OPAQUE_VALUE_ATTRIBUTE;
			} else if (attrbute_name[1] == 's') {
				return SENML_JSON_STRING_VALUE_ATTRIBUTE;
			}
		}
	} else if (fd->name_len == 3) {
		if (attrbute_name[0] == 'v' && attrbute_name[1] == 'l' && attrbute_name[2] == 'o') {
			return SENML_JSON_OBJ_LINK_VALUE_ATTRIBUTE;
		}
	}

	return SENML_JSON_UNKNOWN_ATTRIBUTE;
}

/* Parse SenML attribute & value pairs  */
static int json_next_token(struct lwm2m_input_context *in, struct json_in_formatter_data *fd)
{
	uint8_t cont, c = 0;
	bool escape = false;
	struct lwm2m_senml_json_context *block_ctx;

	(void)memset(fd, 0, sizeof(*fd));
	cont = 1U;
	block_ctx = seml_json_context_get(in->block_ctx);

	if (block_ctx && block_ctx->json_flags) {
		/* Store from last sequence */
		fd->json_flags = block_ctx->json_flags;
		block_ctx->json_flags = 0;
	}

	/* We will be either at start, or at a specific position */
	while (in->offset < in->in_cpkt->offset && cont) {
		fd->offset = in->offset;
		if (buf_read_u8(&c, CPKT_BUF_READ(in->in_cpkt), &in->offset) < 0) {
			break;
		}

		if (c == '\\') {
			escape = true;
			/* Keep track of the escape codes */
			json_add_char(in, fd);
			continue;
		}

		switch (c) {
		case '[':
			if (!escape) {
				fd->json_flags |= T_OBJECT_BEGIN;
				cont = 0U;
			} else {
				json_add_char(in, fd);
			}
			break;
		case '}':
		case ']':
			if (!escape) {
				fd->json_flags |= T_OBJECT_END;
				cont = 0U;
			} else {
				json_add_char(in, fd);
			}
			break;
		case '{':
			if (!escape) {
				fd->json_flags |= T_OBJECT_BEGIN;
			} else {
				json_add_char(in, fd);
			}

			break;


		case ',':
			if (!escape) {
				cont = 0U;
			} else {
				json_add_char(in, fd);
			}

			break;

		case '"':
			if (!escape) {
				if (fd->json_flags & T_STRING_BEGIN) {
					fd->json_flags &= ~T_STRING_BEGIN;
					fd->json_flags |= T_STRING_END;
				} else {
					fd->json_flags &= ~T_STRING_END;
					fd->json_flags |= T_STRING_BEGIN;
				}
			} else {
				json_add_char(in, fd);
			}

			break;

		case ':':
			if (!escape) {
				fd->json_flags &= ~T_STRING_END;
				fd->json_flags |= T_VALUE;
			} else {
				json_add_char(in, fd);
			}

			break;

		/* ignore whitespace */
		case ' ':
		case '\n':
		case '\t':
			if (!(fd->json_flags & T_STRING_BEGIN)) {
				break;
			}

			__fallthrough;

		default:
			json_add_char(in, fd);
		}

		if (escape) {
			escape = false;
		}
	}

	/* OK if cont == 0 othewise we failed */
	return (cont == 0U);
}

static size_t put_begin(struct lwm2m_output_context *out, struct lwm2m_obj_path *path)
{
	struct json_out_formatter_data *fd;

	fd = engine_get_out_user_data(out);
	if (!fd) {
		return 0;
	}

	if (buf_append(CPKT_BUF_WRITE(out->out_cpkt), "[", 1) < 0) {
		return 0;
	}

	/*
	 * Enable base name add if it is enabled
	 * Base name is only added one time at first resource data
	 */
	fd->add_base_name_to_start = fd->base_name_used;
	return 1;
}

static size_t put_end(struct lwm2m_output_context *out, struct lwm2m_obj_path *path)
{
	struct json_out_formatter_data *fd;

	fd = engine_get_out_user_data(out);
	if (!fd) {
		return 0;
	}

	/* Clear flag. */
	fd->add_base_name_to_start = false;

	if (buf_append(CPKT_BUF_WRITE(out->out_cpkt), "]", 1) < 0) {
		return 0;
	}

	return 1;
}

static size_t put_begin_ri(struct lwm2m_output_context *out, struct lwm2m_obj_path *path)
{
	struct json_out_formatter_data *fd;

	fd = engine_get_out_user_data(out);
	if (!fd) {
		return 0;
	}

	fd->writer_flags |= WRITER_RESOURCE_INSTANCE;
	return 0;
}

static size_t put_end_ri(struct lwm2m_output_context *out, struct lwm2m_obj_path *path)
{
	struct json_out_formatter_data *fd;

	fd = engine_get_out_user_data(out);
	if (!fd) {
		return 0;
	}

	fd->writer_flags &= ~WRITER_RESOURCE_INSTANCE;
	return 0;
}

static size_t put_char(struct lwm2m_output_context *out, char c)
{
	if (buf_append(CPKT_BUF_WRITE(out->out_cpkt), &c, sizeof(c)) < 0) {
		return 0;
	}

	return 1;
}

static size_t put_json_prefix(struct lwm2m_output_context *out, struct lwm2m_obj_path *path,
			      const char *format)
{
	struct json_out_formatter_data *fd;
	char *sep;
	int len = 0;
	int base_name_length = 0;

	fd = engine_get_out_user_data(out);

	/* Add separator after first added resource */
	sep = SEPARATOR(fd->writer_flags);
	if (!fd->base_name_used) {
		if (fd->writer_flags & WRITER_RESOURCE_INSTANCE) {
			len = snprintk(json_buffer, sizeof(json_buffer),
				       "%s{\"n\":\"/%u/%u/%u/%u\",%s:", sep, path->obj_id,
				       path->obj_inst_id, path->res_id, path->res_inst_id, format);
		} else {
			len = snprintk(json_buffer, sizeof(json_buffer),
				       "%s{\"n\":\"/%u/%u/%u\",%s:", sep, path->obj_id,
				       path->obj_inst_id, path->res_id, format);
		}
	} else {
		if (fd->add_base_name_to_start) {
			/* Generate base name */
			if (fd->base_name.level == 0) {
				base_name_length = snprintk(json_buffer, sizeof(json_buffer),
							    "%s{\"bn\":\"/\",", sep);
			} else if (fd->base_name.level == 1U) {
				base_name_length =
					snprintk(json_buffer, sizeof(json_buffer),
						 "%s{\"bn\":\"/%u/\",", sep, path->obj_id);
			} else {
				base_name_length = snprintk(json_buffer, sizeof(json_buffer),
							    "%s{\"bn\":\"/%u/%u/\",", sep,
							    path->obj_id, path->obj_inst_id);
			}
			fd->add_base_name_to_start = false;
		} else {
			base_name_length = snprintk(json_buffer, sizeof(json_buffer), "%s{", sep);
		}

		if (base_name_length < 0) {
			return 0;
		}

		if (buf_append(CPKT_BUF_WRITE(out->out_cpkt), json_buffer, base_name_length) < 0) {
			return 0;
		}

		if (fd->base_name.level == 0) {
			if (fd->writer_flags & WRITER_RESOURCE_INSTANCE) {
				len = snprintk(json_buffer, sizeof(json_buffer),
					       "\"n\":\"%u/%u/%u/%u\",%s:", path->obj_id,
					       path->obj_inst_id, path->res_id, path->res_inst_id,
					       format);
			} else {
				len = snprintk(json_buffer, sizeof(json_buffer),
					       "\"n\":\"%u/%u/%u\",%s:", path->obj_id,
					       path->obj_inst_id, path->res_id, format);
			}
		} else if (fd->base_name.level == 1U) {
			if (fd->writer_flags & WRITER_RESOURCE_INSTANCE) {
				len = snprintk(json_buffer, sizeof(json_buffer),
					       "\"n\":\"%u/%u/%u\",%s:", path->obj_inst_id,
					       path->res_id, path->res_inst_id, format);
			} else {
				len = snprintk(json_buffer, sizeof(json_buffer),
					       "\"n\":\"%u/%u\",%s:", path->obj_inst_id,
					       path->res_id, format);
			}
		} else {
			if (fd->writer_flags & WRITER_RESOURCE_INSTANCE) {
				len = snprintk(json_buffer, sizeof(json_buffer),
					       "\"n\":\"%u/%u\",%s:", path->res_id,
					       path->res_inst_id, format);
			} else {
				len = snprintk(json_buffer, sizeof(json_buffer),
					       "\"n\":\"%u\",%s:", path->res_id, format);
			}
		}
	}

	if (len < 0) {
		return 0;
	}

	if (buf_append(CPKT_BUF_WRITE(out->out_cpkt), json_buffer, len) < 0) {
		return 0;
	}

	return len + base_name_length;
}

static size_t put_json_postfix(struct lwm2m_output_context *out)
{
	struct json_out_formatter_data *fd;

	fd = engine_get_out_user_data(out);

	if (put_char(out, '}') < 1) {
		return 0;
	}

	fd->writer_flags |= WRITER_OUTPUT_VALUE;
	return 1;
}

static size_t put_s32(struct lwm2m_output_context *out, struct lwm2m_obj_path *path, int32_t value)
{
	uint16_t original_offset;

	if (!out->out_cpkt || !engine_get_out_user_data(out)) {
		return 0;
	}
	original_offset = out->out_cpkt->offset;

	if (put_json_prefix(out, path, "\"v\"") == 0) {
		goto clean_buf;
	}

	if (plain_text_put_format(out, "%d", value) == 0) {
		goto clean_buf;
	}

	if (put_json_postfix(out) == 0) {
		goto clean_buf;
	}

	return (size_t)out->out_cpkt->offset - original_offset;

clean_buf:
	/* Put Packet offset back to original */
	out->out_cpkt->offset = original_offset;
	return 0;
}

static size_t put_s16(struct lwm2m_output_context *out, struct lwm2m_obj_path *path, int16_t value)
{
	return put_s32(out, path, (int32_t)value);
}

static size_t put_s8(struct lwm2m_output_context *out, struct lwm2m_obj_path *path, int8_t value)
{
	return put_s32(out, path, (int32_t)value);
}

static size_t put_s64(struct lwm2m_output_context *out, struct lwm2m_obj_path *path, int64_t value)
{
	uint16_t original_offset;

	if (!out->out_cpkt || !engine_get_out_user_data(out)) {
		return 0;
	}
	original_offset = out->out_cpkt->offset;

	if (put_json_prefix(out, path, "\"v\"") == 0) {
		goto clean_buf;
	}

	if (plain_text_put_format(out, "%lld", value) == 0) {
		goto clean_buf;
	}

	if (put_json_postfix(out) == 0) {
		goto clean_buf;
	}

	return (size_t)out->out_cpkt->offset - original_offset;

clean_buf:
	/* Put Packet offset back to original */
	out->out_cpkt->offset = original_offset;
	return 0;
}

static int write_string_buffer(struct lwm2m_output_context *out, char *buf, size_t buflen)
{
	if (put_char(out, '"') == 0) {
		return -1;
	}

	int res;

	for (size_t i = 0; i < buflen; ++i) {
		/* Escape special characters */
		/* TODO: Handle UTF-8 strings */
		if (buf[i] < '\x20') {
			res = snprintk(json_buffer, sizeof(json_buffer), "\\x%x", buf[i]);
			if (res < 0) {
				return -1;
			}

			if (buf_append(CPKT_BUF_WRITE(out->out_cpkt), json_buffer, res) < 0) {
				return -1;
			}

			continue;
		} else if (buf[i] == '"' || buf[i] == '\\') {
			if (put_char(out, '\\') == 0) {
				return -1;
			}
		}

		if (put_char(out, buf[i]) == 0) {
			return -1;
		}
	}

	if (put_char(out, '"') == 0) {
		return -1;
	}

	return 0;
}

static size_t put_string(struct lwm2m_output_context *out, struct lwm2m_obj_path *path, char *buf,
			 size_t buflen)
{
	uint16_t original_offset;

	if (!out->out_cpkt || !engine_get_out_user_data(out)) {
		return 0;
	}
	original_offset = out->out_cpkt->offset;

	if (put_json_prefix(out, path, "\"vs\"") == 0) {
		goto clean_buf;
	}

	if (write_string_buffer(out, buf, buflen)) {
		goto clean_buf;
	}

	if (put_json_postfix(out) == 0) {
	}
	return (size_t)out->out_cpkt->offset - original_offset;

clean_buf:
	/* Put Packet offset back to original */
	out->out_cpkt->offset = original_offset;
	return 0;
}

static size_t put_float(struct lwm2m_output_context *out, struct lwm2m_obj_path *path,
			     double  *value)
{
	uint16_t original_offset;

	if (!out->out_cpkt || !engine_get_out_user_data(out)) {
		return 0;
	}
	original_offset = out->out_cpkt->offset;

	if (put_json_prefix(out, path, "\"v\"") == 0) {
		goto clean_buf;
	}

	if (plain_text_put_float(out, path, value) == 0) {
		goto clean_buf;
	}

	if (put_json_postfix(out) == 0) {
		goto clean_buf;
	}

	return (size_t)out->out_cpkt->offset - original_offset;

clean_buf:
	/* Put Packet offset back to original */
	out->out_cpkt->offset = original_offset;
	return 0;
}

static size_t put_bool(struct lwm2m_output_context *out, struct lwm2m_obj_path *path, bool value)
{
	uint16_t original_offset;

	if (!out->out_cpkt || !engine_get_out_user_data(out)) {
		return 0;
	}
	original_offset = out->out_cpkt->offset;

	if (put_json_prefix(out, path, "\"vb\"") == 0) {
		goto clean_buf;
	}

	if (plain_text_put_format(out, "%s", value ? "true" : "false") == 0) {
		goto clean_buf;
	}

	if (put_json_postfix(out) == 0) {
		goto clean_buf;
	}

	return (size_t)out->out_cpkt->offset - original_offset;

clean_buf:
	/* Put Packet offset back to original */
	out->out_cpkt->offset = original_offset;
	return 0;
}

static int write_opaque_buffer(struct lwm2m_output_context *out, char *buf, size_t buflen)
{
	if (put_char(out, '"') == 0) {
		return -1;
	}
	size_t temp_length;

	if (base64_encode(CPKT_BUF_PTR(out->out_cpkt), CPKT_BUF_SIZE(out->out_cpkt), &temp_length,
			  buf, buflen)) {
		/* No space available for base64 data */
		return -1;
	}
	out->out_cpkt->offset += temp_length;

	if (put_char(out, '"') == 0) {
		return -1;
	}

	return 0;
}

static size_t put_opaque(struct lwm2m_output_context *out, struct lwm2m_obj_path *path, char *buf,
			 size_t buflen)
{
	uint16_t original_offset;

	if (!out->out_cpkt || !engine_get_out_user_data(out)) {
		return 0;
	}
	original_offset = out->out_cpkt->offset;

	if (put_json_prefix(out, path, "\"vd\"") == 0) {
		goto clean_buf;
	}

	if (write_opaque_buffer(out, buf, buflen)) {
		/* No space available for base64 data*/
		goto clean_buf;
	}

	if (put_json_postfix(out) == 0) {
		goto clean_buf;
	}

	return (size_t)out->out_cpkt->offset - original_offset;

clean_buf:
	/* Put Packet offset back to original */
	out->out_cpkt->offset = original_offset;
	return 0;
}

static size_t put_objlnk(struct lwm2m_output_context *out, struct lwm2m_obj_path *path,
			 struct lwm2m_objlnk *value)
{
	uint16_t original_offset;

	if (!out->out_cpkt || !engine_get_out_user_data(out)) {
		return 0;
	}
	original_offset = out->out_cpkt->offset;

	if (put_json_prefix(out, path, "\"vlo\"") == 0) {
		goto clean_buf;
	}

	if (plain_text_put_format(out, "\"%u:%u\"", value->obj_id, value->obj_inst) == 0) {
		goto clean_buf;
	}

	if (put_json_postfix(out) == 0) {
		goto clean_buf;
	}

	return (size_t)out->out_cpkt->offset - original_offset;

clean_buf:
	/* Put Packet offset back to original */
	out->out_cpkt->offset = original_offset;
	return 0;
}

static size_t read_int(struct lwm2m_input_context *in, int64_t *value, bool accept_sign)
{
	struct json_in_formatter_data *fd;
	uint8_t *buf;
	size_t i = 0;
	bool neg = false;
	char c;

	/* initialize values to 0 */
	*value = 0;

	fd = engine_get_in_user_data(in);
	if (!fd) {
		return 0;
	}

	buf = in->in_cpkt->data + fd->value_offset;
	while (*(buf + i) && i < fd->value_len) {
		c = *(buf + i);
		if (c == '-' && accept_sign && i == 0) {
			neg = true;
		} else if (isdigit(c)) {
			*value = *value * 10 + (c - '0');
		} else {
			/* anything else stop reading */
			break;
		}

		i++;
	}

	if (neg) {
		*value = -*value;
	}

	return i;
}

static size_t get_s64(struct lwm2m_input_context *in, int64_t *value)
{
	return read_int(in, value, true);
}

static size_t get_s32(struct lwm2m_input_context *in, int32_t *value)
{
	int64_t tmp = 0;
	size_t len = 0;

	len = read_int(in, &tmp, true);
	if (len > 0) {
		*value = (int32_t)tmp;
	}

	return len;
}

static size_t get_string(struct lwm2m_input_context *in, uint8_t *buf, size_t buflen)
{
	struct json_in_formatter_data *fd;
	int ret;

	fd = engine_get_in_user_data(in);
	if (!fd) {
		return 0;
	}

	if (fd->value_len > buflen) {
		/* TODO: generate warning? */
		fd->value_len = buflen - 1;
	}

	ret = buf_read(buf, fd->value_len, CPKT_BUF_READ(in->in_cpkt), &fd->value_offset);

	if (ret < 0) {
		return 0;
	}
	/* add NULL */
	buf[fd->value_len] = '\0';

	return fd->value_len;
}

static size_t get_float(struct lwm2m_input_context *in, double *value)
{
	struct json_in_formatter_data *fd;

	size_t i = 0, len = 0;
	bool has_dot = false;
	uint8_t tmp, buf[24];
	uint8_t *json_buf;

	fd = engine_get_in_user_data(in);
	if (!fd) {
		return 0;
	}

	json_buf = in->in_cpkt->data + fd->value_offset;
	while (*(json_buf + len) && len < fd->value_len) {
		tmp = *(json_buf + len);

		if ((tmp == '-' && i == 0) || (tmp == '.' && !has_dot) || isdigit(tmp)) {
			len++;

			/* Copy only if it fits into provided buffer - we won't
			 * get better precision anyway.
			 */
			if (i < sizeof(buf) - 1) {
				buf[i++] = tmp;
			}

			if (tmp == '.') {
				has_dot = true;
			}
		} else {
			break;
		}
	}

	buf[i] = '\0';

	if (lwm2m_atof32(buf, value) != 0) {
		LOG_ERR("Failed to parse float value");
	}

	return len;
}

static size_t get_bool(struct lwm2m_input_context *in, bool *value)
{
	struct json_in_formatter_data *fd;

	fd = engine_get_in_user_data(in);
	if (!fd) {
		return 0;
	}

	if (strncmp(in->in_cpkt->data + fd->value_offset, "true", 4) == 0) {
		*value = true;
	} else if (strncmp(in->in_cpkt->data + fd->value_offset, "false", 5) == 0) {
		*value = false;
	}

	return fd->value_len;
}

static size_t get_opaque(struct lwm2m_input_context *in, uint8_t *value, size_t buflen,
			 struct lwm2m_opaque_context *opaque, bool *last_block)
{
	struct json_in_formatter_data *fd;
	struct lwm2m_senml_json_context *block_ctx;

	block_ctx = seml_json_context_get(in->block_ctx);

	fd = engine_get_in_user_data(in);
	if (!fd) {
		return 0;
	}

	uint8_t *data_ptr = in->in_cpkt->data + fd->value_offset;

	if (opaque->remaining == 0) {
		size_t original_size = fd->value_len;
		size_t base64_length;

		if (block_ctx) {
			if (block_ctx->base64_buf_len) {
				uint8_t module_buf[4];
				size_t buffer_module_length = 4 - block_ctx->base64_buf_len;

				if (fd->value_len < buffer_module_length) {
					return 0;
				}

				fd->value_len -= buffer_module_length;
				memcpy(module_buf, block_ctx->base64_mod_buf,
				       block_ctx->base64_buf_len);
				memcpy(module_buf + block_ctx->base64_buf_len, data_ptr,
				       buffer_module_length);

				size_t buffer_base64_length;

				if (base64_decode(module_buf, 4, &buffer_base64_length, module_buf,
						  4) < 0) {
					return 0;
				}

				block_ctx->base64_buf_len = 0;

				if (!in->block_ctx->last_block) {
					block_ctx->base64_buf_len = (fd->value_len % 4);
					if (fd->value_len < block_ctx->base64_buf_len) {
						return 0;
					}

					if (block_ctx->base64_buf_len) {
						uint8_t *data_tail_ptr;

						data_tail_ptr =
							data_ptr + (original_size -
								    block_ctx->base64_buf_len);
						memcpy(block_ctx->base64_mod_buf, data_tail_ptr,
						       block_ctx->base64_buf_len);
						fd->value_len -= block_ctx->base64_buf_len;
					}
				}
				/* Decode rest of data and do memmove */
				if (base64_decode(data_ptr, original_size, &base64_length,
						  data_ptr + buffer_module_length,
						  fd->value_len) < 0) {
					return 0;
				}
				fd->value_len = base64_length;
				/* Move decoded data by module result size frtom front */
				memmove(data_ptr + buffer_base64_length, data_ptr, fd->value_len);
				memcpy(data_ptr, module_buf, buffer_base64_length);
				fd->value_len += buffer_base64_length;
			} else {
				block_ctx->base64_buf_len = (fd->value_len % 4);
				if (fd->value_len < block_ctx->base64_buf_len) {
					return 0;
				}

				if (block_ctx->base64_buf_len) {
					uint8_t *data_tail_ptr =
						data_ptr +
						(original_size - block_ctx->base64_buf_len);

					memcpy(block_ctx->base64_mod_buf, data_tail_ptr,
					       block_ctx->base64_buf_len);
					fd->value_len -= block_ctx->base64_buf_len;
				}

				if (base64_decode(data_ptr, original_size, &base64_length, data_ptr,
						  fd->value_len) < 0) {
					return 0;
				}
				fd->value_len = base64_length;
			}
			/* Set zero because total length is unknown */
			opaque->len = 0;
		} else {
			if (base64_decode(data_ptr, fd->value_len, &base64_length, data_ptr,
					  fd->value_len) < 0) {
				return 0;
			}
			fd->value_len = base64_length;
			opaque->len = fd->value_len;
		}
		opaque->remaining = fd->value_len;
	}

	size_t in_len = opaque->remaining;

	if (in_len > buflen) {
		in_len = buflen;
	}

	if (in_len > fd->value_len) {
		in_len = fd->value_len;
	}

	opaque->remaining -= in_len;
	if (opaque->remaining == 0U) {
		*last_block = true;
	}
	/* Copy data to buffer */
	memcpy(value, data_ptr, in_len);

	return (size_t)in_len;
}

static size_t get_objlnk(struct lwm2m_input_context *in, struct lwm2m_objlnk *value)
{
	int64_t tmp;
	size_t len;
	uint16_t value_offset;
	struct json_in_formatter_data *fd;

	fd = engine_get_in_user_data(in);
	if (!fd) {
		return 0;
	}

	/* Store the original value offset. */
	value_offset = fd->value_offset;

	len = read_int(in, &tmp, false);
	value->obj_id = (uint16_t)tmp;

	len++; /* +1 for ':' delimeter. */
	fd->value_offset += len;

	len += read_int(in, &tmp, false);
	value->obj_inst = (uint16_t)tmp;

	/* Restore the original value offset. */
	fd->value_offset = value_offset;

	return len;
}

const struct lwm2m_writer senml_json_writer = {
	.put_begin = put_begin,
	.put_end = put_end,
	.put_begin_ri = put_begin_ri,
	.put_end_ri = put_end_ri,
	.put_s8 = put_s8,
	.put_s16 = put_s16,
	.put_s32 = put_s32,
	.put_s64 = put_s64,
	.put_string = put_string,
	.put_float = put_float,
	.put_bool = put_bool,
	.put_opaque = put_opaque,
	.put_objlnk = put_objlnk,
};

const struct lwm2m_reader senml_json_reader = {
	.get_s32 = get_s32,
	.get_s64 = get_s64,
	.get_string = get_string,
	.get_float = get_float,
	.get_bool = get_bool,
	.get_opaque = get_opaque,
	.get_objlnk = get_objlnk,
};

static uint8_t lwm2m_use_base_name(struct lwm2m_obj_path path_list[], uint8_t path_list_size)
{
	uint8_t recursive_path = 0;

	for (int i = 0; i < path_list_size; i++) {
		if (path_list[i].level < 3) {
			recursive_path++;
		}
	}
	return recursive_path;
}

static void lwm2m_define_longest_match_url_for_base_name(struct json_out_formatter_data *fd,
							 struct lwm2m_obj_path path_list[],
							 uint8_t path_list_size)
{
	if (!lwm2m_use_base_name(path_list, path_list_size)) {
		/* do not use base at all */
		fd->base_name_used = false;
		return;
	}

	/* First at list is define compare for rest */
	fd->base_name.level = path_list[0].level;
	fd->base_name.obj_id = path_list[0].obj_id;
	fd->base_name.obj_inst_id = path_list[0].obj_inst_id;
	fd->base_name.res_id = path_list[0].res_id;
	fd->base_name.res_inst_id = path_list[0].res_inst_id;

	fd->base_name_used = true;

	if (fd->base_name.level == 0) {
		return;
	}

	for (int i = 1; i < path_list_size; i++) {
		if (path_list[i].level == 0 || fd->base_name.obj_id != path_list[i].obj_id) {
			/*
			 * Stop if Object ID is not match or compare url level is 0
			 * Define just "/" base name
			 */
			fd->base_name.level = 0;
			return;
		}

		if (fd->base_name.level == 1U) {
			continue;
		}

		if (fd->base_name.level >= path_list[i].level &&
		    fd->base_name.obj_inst_id != path_list[i].obj_inst_id) {
			/* Define just "/obj_id/" base name */
			fd->base_name.level = 1;
			continue;
		}

		if (fd->base_name.level == 2U) {
			continue;
		}

		if (fd->base_name.level >= path_list[i].level &&
		    fd->base_name.res_id != path_list[i].res_id) {
			/* Do not continue deeper possible bn "/obj_id/obj_inst_id/" */
			fd->base_name.level = 2;
			continue;
		}

		if (fd->base_name.level == 3U) {
			continue;
		}

		if (fd->base_name.level >= path_list[i].level &&
		    fd->base_name.res_inst_id != path_list[i].res_inst_id) {
			/* Do not continue deeper possible bn "/obj_id/obj_inst_id/res_id/" */
			fd->base_name.level = 3;
			continue;
		}
	}
}

void lwm2m_senml_json_context_init(struct lwm2m_senml_json_context *ctx)
{
	ctx->base_name_stored = false;
	ctx->full_name_true = false;
	ctx->base64_buf_len = 0;
	ctx->json_flags = 0;
}

int do_read_op_senml_json(struct lwm2m_message *msg)
{
	struct lwm2m_obj_path path;
	int ret;
	struct json_out_formatter_data fd;

	(void)memset(&fd, 0, sizeof(fd));
	engine_set_out_user_data(&msg->out, &fd);
	/* Init message here ready for response */
	path = msg->path;

	/* Detect longest match base name to url */
	lwm2m_define_longest_match_url_for_base_name(&fd, &path, 1);

	ret = lwm2m_perform_read_op(msg, LWM2M_FORMAT_APP_SEML_JSON);
	engine_clear_out_user_data(&msg->out);

	return ret;
}

static int parse_path(const uint8_t *buf, uint16_t buflen, struct lwm2m_obj_path *path)
{
	int ret = 0;
	int pos = 0;
	uint16_t val;
	uint8_t c = 0U;

	(void)memset(path, 0, sizeof(*path));
	do {
		val = 0U;
		c = buf[pos];
		/* we should get a value first - consume all numbers */
		while (pos < buflen && isdigit(c)) {
			val = val * 10U + (c - '0');
			c = buf[++pos];
		}

		/* slash will mote thing forward */
		if (pos == 0 && c == '/') {
			/* skip leading slashes */
			pos++;
		} else if (c == '/' || pos == buflen) {
			LOG_DBG("Setting %u = %u", ret, val);
			if (ret == 0) {
				path->obj_id = val;
			} else if (ret == 1) {
				path->obj_inst_id = val;
			} else if (ret == 2) {
				path->res_id = val;
			} else if (ret == 3) {
				path->res_inst_id = val;
			}

			ret++;
			pos++;
		} else {
			LOG_ERR("Error: illegal char '%c' at pos:%d", c, pos);
			return -1;
		}
	} while (pos < buflen);

	return ret;
}

static int lwm2m_senml_write_operation(struct lwm2m_message *msg, struct json_in_formatter_data *fd)
{
	struct lwm2m_engine_obj_field *obj_field = NULL;
	struct lwm2m_engine_obj_inst *obj_inst = NULL;
	struct lwm2m_engine_res *res = NULL;
	struct lwm2m_engine_res_inst *res_inst = NULL;
	uint8_t created;
	int ret = 0;

	/* handle resource value */
	/* reset values */
	created = 0U;

	/* if valid, use the return value as level */

	ret = lwm2m_get_or_create_engine_obj(msg, &obj_inst, &created);
	if (ret < 0) {
		return ret;
	}

	obj_field = lwm2m_get_engine_obj_field(obj_inst->obj, msg->path.res_id);
	/*
	 * if obj_field is not found,
	 * treat as an optional resource
	 */
	if (!obj_field) {
		return -ENOENT;
	}

	if (!LWM2M_HAS_PERM(obj_field, LWM2M_PERM_W)) {
		return -EPERM;
	}

	if (!obj_inst->resources || obj_inst->resource_count == 0U) {
		return -EINVAL;
	}

	for (int index = 0; index < obj_inst->resource_count; index++) {
		if (obj_inst->resources[index].res_id == msg->path.res_id) {
			res = &obj_inst->resources[index];
			break;
		}
	}

	if (!res) {
		return -ENOENT;
	}

	for (int index = 0; index < res->res_inst_count; index++) {
		if (res->res_instances[index].res_inst_id == msg->path.res_inst_id) {
			res_inst = &res->res_instances[index];
			break;
		}
	}

	if (!res_inst) {
		return -ENOENT;
	}

	/* Write the resource value */
	ret = lwm2m_write_handler(obj_inst, res, res_inst, obj_field, msg);
	return ret;
}

static int senml_json_path_to_string(uint8_t *buf, size_t buf_len, struct lwm2m_obj_path *path,
				     uint8_t path_level)
{
	int name_length;

	if (path_level == 0) {
		name_length = snprintk(buf, buf_len, "/");
	} else if (path_level == 1U) {
		name_length = snprintk(buf, buf_len, "/%u/", path->obj_id);
	} else if (path_level == 2U) {
		name_length = snprintk(buf, buf_len, "/%u/%u/", path->obj_id, path->obj_inst_id);
	} else if (path_level == 3U) {
		name_length = snprintk(buf, buf_len, "/%u/%u/%u", path->obj_id, path->obj_inst_id,
				       path->res_id);
	} else {
		name_length = snprintk(buf, buf_len, "/%u/%u/%u/%u", path->obj_id,
				       path->obj_inst_id, path->res_id, path->res_inst_id);
	}

	if (name_length > 0) {
		buf[name_length] = '\0';
	}

	return name_length;
}

int do_write_op_senml_json(struct lwm2m_message *msg)
{
	struct json_in_formatter_data fd;
	int ret = 0;
	uint8_t name[MAX_RESOURCE_LEN + 1];
	uint8_t base_name[MAX_RESOURCE_LEN + 1];
	uint8_t full_name[MAX_RESOURCE_LEN + 1];
	struct lwm2m_obj_path resource_path;
	bool path_valid = false;
	bool data_value = false;
	struct lwm2m_senml_json_context *block_ctx;

	(void)memset(&fd, 0, sizeof(fd));
	engine_set_in_user_data(&msg->in, &fd);

	block_ctx = seml_json_context_get(msg->in.block_ctx);

	if (block_ctx && block_ctx->json_flags) {
		int name_length;

		/* Re-load Base name and Name data from context block */
		if (block_ctx->base_name_stored) {
			/* base name path generate to string */
			name_length = senml_json_path_to_string(base_name, sizeof(base_name),
								&block_ctx->base_name_path,
								block_ctx->base_name_path.level);

			if (name_length <= 0) {
				ret = -EINVAL;
				goto end_of_operation;
			}

			if (block_ctx->base_name_path.level >= 3U && !block_ctx->full_name_true) {
				memcpy(full_name, base_name, MAX_RESOURCE_LEN + 1);
				ret = parse_path(full_name, strlen(full_name), &resource_path);
				if (ret < 0) {
					ret = -EINVAL;
					goto end_of_operation;
				}
				resource_path.level = ret;
				path_valid = true;
			}
		}

		if (block_ctx->full_name_true) {
			/* full name path generate to string */
			name_length = senml_json_path_to_string(full_name, sizeof(full_name),
								&block_ctx->base_name_path,
								block_ctx->resource_path_level);

			if (name_length <= 0) {
				ret = -EINVAL;
				goto end_of_operation;
			}

			ret = parse_path(full_name, strlen(full_name), &resource_path);
			if (ret < 0) {
				ret = -EINVAL;
				goto end_of_operation;
			}
			resource_path.level = ret;
			path_valid = true;
		}
	}

	/* Parse Attribute value pair */
	while (json_next_token(&msg->in, &fd)) {
		if (!(fd.json_flags & T_VALUE)) {
			continue;
		}

		data_value = false;

		switch (json_atribute_decode(&msg->in, &fd)) {
		case SENML_JSON_BASE_NAME_ATTRIBUTE:
			if (fd.value_len > MAX_RESOURCE_LEN) {
				LOG_ERR("Base name too long %u", fd.value_len);
				ret = -EINVAL;
				goto end_of_operation;
			}

			if (buf_read(base_name, fd.value_len, CPKT_BUF_READ(msg->in.in_cpkt),
				     &fd.value_offset) < 0) {
				LOG_ERR("Error parsing base name!");
				ret = -EINVAL;
				goto end_of_operation;
			}

			base_name[fd.value_len] = '\0';
			/* Relative name is optional - preinitialize full name with base name */
			snprintk(full_name, sizeof(full_name), "%s", base_name);
			ret = parse_path(full_name, strlen(full_name), &resource_path);
			if (ret < 0) {
				LOG_ERR("Relative name too long");
				ret = -EINVAL;
				goto end_of_operation;
			}
			resource_path.level = ret;

			if (resource_path.level) {
				path_valid = true;
			}

			if (block_ctx) {
				block_ctx->base_name_path = resource_path;
				block_ctx->base_name_stored = true;
			}

			break;
		case SENML_JSON_NAME_ATTRIBUTE:

			/* handle resource name */
			if (fd.value_len > MAX_RESOURCE_LEN) {
				LOG_ERR("Relative name too long");
				ret = -EINVAL;
				goto end_of_operation;
			}

			/* get value for relative path */
			if (buf_read(name, fd.value_len, CPKT_BUF_READ(msg->in.in_cpkt),
				     &fd.value_offset) < 0) {
				LOG_ERR("Error parsing relative path!");
				ret = -EINVAL;
				goto end_of_operation;
			}

			name[fd.value_len] = '\0';

			/* combine base_name + name */
			snprintk(full_name, sizeof(full_name), "%s%s", base_name, name);
			ret = parse_path(full_name, strlen(full_name), &resource_path);
			if (ret < 0) {
				LOG_ERR("Relative name too long");
				ret = -EINVAL;
				goto end_of_operation;
			}
			resource_path.level = ret;

			if (block_ctx) {
				/* Store Resource data Path to base name path but
				 * store separately path level
				 */
				uint8_t path_level = block_ctx->base_name_path.level;

				block_ctx->base_name_path = resource_path;
				block_ctx->resource_path_level = resource_path.level;
				block_ctx->base_name_path.level = path_level;
				block_ctx->full_name_true = true;
			}
			path_valid = true;
			break;

		case SENML_JSON_FLOAT_VALUE_ATTRIBUTE:
		case SENML_JSON_BOOLEAN_VALUE_ATTRIBUTE:
		case SENML_JSON_OBJ_LINK_VALUE_ATTRIBUTE:
		case SENML_JSON_OPAQUE_VALUE_ATTRIBUTE:
		case SENML_JSON_STRING_VALUE_ATTRIBUTE:
		case SENML_JSON_STRING_BLOCK_DATA:
			data_value = true;
			break;

		case SENML_JSON_UNKNOWN_ATTRIBUTE:
			LOG_ERR("Unknown attribute");
			ret = -EINVAL;
			goto end_of_operation;

		default:
			break;
		}

		if (data_value && path_valid) {
			/* parse full_name into path */
			if (block_ctx) {
				/* Store json Flags */
				block_ctx->json_flags = fd.json_flags;
			}

			msg->path = resource_path;
			ret = lwm2m_senml_write_operation(msg, &fd);

			if (ret < 0) {
				break;
			}
		}
	}
	/* Do we have a data value which is part of the CoAP blocking process */
	if ((fd.json_flags & T_VALUE) && !(fd.json_flags & T_OBJECT_END) && !data_value &&
	    block_ctx && fd.value_len) {
		if (!path_valid) {
			LOG_ERR("No path available for Coap Block sub sequency");
			ret = -EINVAL;
			goto end_of_operation;
		}
		/* Store Json File description flags */
		block_ctx->json_flags = fd.json_flags;
		msg->path = resource_path;
		ret = lwm2m_senml_write_operation(msg, &fd);
	}

end_of_operation:
	engine_clear_in_user_data(&msg->in);

	return ret;
}
