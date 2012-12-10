/*
 * Common code for dealing with tag, length, value arrays
 * Copyright © 2009-2012, albinoloverats ~ Software Development
 * email: webmaster@albinoloverats.net
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <netinet/in.h>

#include "common/common.h"
#include "common/tlv.h"

typedef struct
{
    size_t tags;
    tlv_t *buffer;
}
tlv_private_t;

extern TLV_HANDLE tlv_init(void)
{
    return calloc(sizeof( tlv_private_t ), sizeof( byte_t ));
}

extern void tlv_deinit(TLV_HANDLE *ptr)
{
    if (!*ptr)
        return;
    tlv_private_t *tlv_ptr = (tlv_private_t *)*ptr;
    for (unsigned i = 0; i < tlv_ptr->tags; i++)
    {
        tlv_t tlv = tlv_ptr->buffer[i];
        tlv.tag = 0;
        tlv.length = 0;
        free(tlv.value);
        tlv.value = NULL;
    }
    tlv_ptr->tags = 0;
    free(tlv_ptr->buffer);
    tlv_ptr->buffer = NULL;
    free(tlv_ptr);
    tlv_ptr = NULL;
    *ptr = NULL;
    return;
}

extern void tlv_append(TLV_HANDLE *ptr, tlv_t tlv)
{
    if (!*ptr)
        return;
    tlv_private_t *tlv_ptr = (tlv_private_t *)*ptr;
    void *z = realloc(tlv_ptr->buffer, (tlv_ptr->tags + 1) * sizeof tlv);
    tlv_ptr->buffer = z;
    tlv_ptr->buffer[tlv_ptr->tags].tag = tlv.tag;
    tlv_ptr->buffer[tlv_ptr->tags].length = tlv.length;
    tlv_ptr->buffer[tlv_ptr->tags].value = malloc(tlv.length);
    memcpy(tlv_ptr->buffer[tlv_ptr->tags].value, tlv.value, tlv.length);
    tlv_ptr->tags++;
    return;
}

extern bool tlv_has_tag(TLV_HANDLE ptr, uint8_t tag)
{
    if (!ptr)
        return false;
    return tlv_value_of(ptr, tag) != NULL;
}

extern uint8_t *tlv_value_of(TLV_HANDLE ptr, uint8_t tag)
{
    if (!ptr)
        return NULL;
    tlv_private_t *tlv_ptr = (tlv_private_t *)ptr;
    for (unsigned i = 0; i < tlv_ptr->tags; i++)
    {
        tlv_t tlv = tlv_ptr->buffer[i];
        if (tlv.tag == tag)
            return tlv.value;
    }
    return NULL;
}

extern uint8_t *tlv_export_aux(TLV_HANDLE ptr, bool nbo)
{
    if (!ptr)
        return NULL;
    tlv_private_t *tlv_ptr = (tlv_private_t *)ptr;
    size_t size = tlv_size(tlv_ptr);
    uint8_t *buf = malloc(size);
    size_t off = 0;
    for (unsigned i = 0; i < tlv_ptr->tags; i++)
    {
        tlv_t tlv = tlv_ptr->buffer[i];
        memcpy(buf + off, &tlv.tag, sizeof tlv.tag);
        off += sizeof tlv.tag;
        uint16_t l = nbo ? htons(tlv.length) : tlv.length;
        memcpy(buf + off, &l, sizeof tlv.length);
        off += sizeof tlv.length;
        memcpy(buf + off, tlv.value, tlv.length);
        off += tlv.length;
    }
    return buf;
}

extern uint16_t tlv_count(TLV_HANDLE ptr)
{
    if (!ptr)
        return 0;
    return ((tlv_private_t *)ptr)->tags;
}

extern size_t tlv_size(TLV_HANDLE ptr)
{
    if (!ptr)
        return 0;
    tlv_private_t *tlv_ptr = (tlv_private_t *)ptr;
    size_t size = 0;
    for (unsigned i = 0; i < tlv_ptr->tags; i++)
        size += sizeof( uint8_t ) + sizeof( uint16_t ) + tlv_ptr->buffer[i].length;
    return size;
}
