#ifndef TARANTOOL_BOX_KEY_DEF_H_INCLUDED
#define TARANTOOL_BOX_KEY_DEF_H_INCLUDED
/*
 * Copyright 2010-2016, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "trivia/util.h"
#include "error.h"
#include "diag.h"
#include <msgpuck.h>
#include <limits.h>
#include "field_def.h"
#include "coll.h"

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

/* MsgPack type names */
extern const char *mp_type_strs[];

struct key_part_def {
	/** Tuple field index for this part. */
	uint32_t fieldno;
	/** Type of the tuple field. */
	enum field_type type;
	/** Collation ID for string comparison. */
	uint32_t coll_id;
	/** True if a key part can store NULLs. */
	bool is_nullable;
};

/**
 * Set key_part_def.coll_id to COLL_NONE if
 * the field does not have a collation.
 */
#define COLL_NONE UINT32_MAX

/** Descriptor of a single part in a multipart key. */
struct key_part {
	/** Tuple field index for this part */
	uint32_t fieldno;
	/** Type of the tuple field */
	enum field_type type;
	/** Collation definition for string comparison */
	struct coll *coll;
	/** True if a part can store NULLs. */
	bool is_nullable;
};

struct key_def;
struct tuple;

/** @copydoc tuple_compare_with_key() */
typedef int (*tuple_compare_with_key_t)(const struct tuple *tuple_a,
					const char *key,
					uint32_t part_count,
					const struct key_def *key_def);
/** @copydoc tuple_compare() */
typedef int (*tuple_compare_t)(const struct tuple *tuple_a,
			       const struct tuple *tuple_b,
			       const struct key_def *key_def);
/** @copydoc tuple_extract_key() */
typedef char *(*tuple_extract_key_t)(const struct tuple *tuple,
				     const struct key_def *key_def,
				     uint32_t *key_size);
/** @copydoc tuple_extract_key_raw() */
typedef char *(*tuple_extract_key_raw_t)(const char *data,
					 const char *data_end,
					 const struct key_def *key_def,
					 uint32_t *key_size);
/** @copydoc tuple_hash() */
typedef uint32_t (*tuple_hash_t)(const struct tuple *tuple,
				 const struct key_def *key_def);
/** @copydoc key_hash() */
typedef uint32_t (*key_hash_t)(const char *key,
				const struct key_def *key_def);

/* Definition of a multipart key. */
struct key_def {
	/** @see tuple_compare() */
	tuple_compare_t tuple_compare;
	/** @see tuple_compare_with_key() */
	tuple_compare_with_key_t tuple_compare_with_key;
	/** @see tuple_extract_key() */
	tuple_extract_key_t tuple_extract_key;
	/** @see tuple_extract_key_raw() */
	tuple_extract_key_raw_t tuple_extract_key_raw;
	/** @see tuple_hash() */
	tuple_hash_t tuple_hash;
	/** @see key_hash() */
	key_hash_t key_hash;
	/**
	 * Minimal part count which always is unique. For example,
	 * if a secondary index is unique, then
	 * unique_part_count == secondary index part count. But if
	 * a secondary index is not unique, then
	 * unique_part_count == part count of a merged key_def.
	 */
	uint32_t unique_part_count;
	/** True, if at least one part can store NULL. */
	bool is_nullable;
	/** Key fields mask. @sa column_mask.h for details. */
	uint64_t column_mask;
	/** The size of the 'parts' array. */
	uint32_t part_count;
	/** Description of parts of a multipart index. */
	struct key_part parts[];
};

/**
 * Duplicate key_def.
 * @param src Original key_def.
 *
 * @retval not NULL Duplicate of src.
 * @retval     NULL Memory error.
 */
struct key_def *
key_def_dup(const struct key_def *src);

/** \cond public */

typedef struct key_def box_key_def_t;

/**
 * Create key definition with key fields with passed typed on passed positions.
 * May be used for tuple format creation and/or tuple comparison.
 *
 * \param fields array with key field identifiers
 * \param types array with key field types (see enum field_type)
 * \param part_count the number of key fields
 * \returns a new key definition object
 */
box_key_def_t *
box_key_def_new(uint32_t *fields, uint32_t *types, uint32_t part_count);

/**
 * Delete key definition
 *
 * \param key_def key definition to delete
 */
void
box_key_def_delete(box_key_def_t *key_def);

/** \endcond public */

static inline size_t
key_def_sizeof(uint32_t part_count)
{
	return sizeof(struct key_def) + sizeof(struct key_part) * part_count;
}

/**
 * Allocate a new key_def with the given part count.
 */
struct key_def *
key_def_new(uint32_t part_count);

/**
 * Allocate a new key_def with the given part count
 * and initialize its parts.
 */
struct key_def *
key_def_new_with_parts(struct key_part_def *parts, uint32_t part_count);

/**
 * Dump part definitions of the given key def.
 */
void
key_def_dump_parts(const struct key_def *def, struct key_part_def *parts);

/**
 * Set a single key part in a key def.
 * @pre part_no < part_count
 */
void
key_def_set_part(struct key_def *def, uint32_t part_no, uint32_t fieldno,
		 enum field_type type, bool is_nullable, struct coll *coll);

/**
 * An snprint-style function to print a key definition.
 */
int
key_def_snprint_parts(char *buf, int size, const struct key_part_def *parts,
		      uint32_t part_count);

/**
 * Return size of key parts array when encoded in MsgPack.
 * See also key_def_encode_parts().
 */
size_t
key_def_sizeof_parts(const struct key_part_def *parts, uint32_t part_count);

/**
 * Encode key parts array in MsgPack and return a pointer following
 * the end of encoded data.
 */
char *
key_def_encode_parts(char *data, const struct key_part_def *parts,
		     uint32_t part_count);

/**
 * Decode parts array from tuple field and write'em to index_def structure.
 * Throws a nice error about invalid types, but does not check ranges of
 *  resulting values field_no and field_type
 * Parts expected to be a sequence of <part_count> arrays like this:
 *  [NUM, STR, ..][NUM, STR, ..]..,
 *  OR
 *  {field=NUM, type=STR, ..}{field=NUM, type=STR, ..}..,
 */
int
key_def_decode_parts(struct key_part_def *parts, uint32_t part_count,
		     const char **data, const struct field_def *fields,
		     uint32_t field_count);

/**
 * Returns the part in index_def->parts for the specified fieldno.
 * If fieldno is not in index_def->parts returns NULL.
 */
const struct key_part *
key_def_find(const struct key_def *key_def, uint32_t fieldno);

/**
 * Allocate a new key_def with a set union of key parts from
 * first and second key defs. Parts of the new key_def consist
 * of the first key_def's parts and those parts of the second
 * key_def that were not among the first parts.
 * @retval not NULL Ok.
 * @retval NULL     Memory error.
 */
struct key_def *
key_def_merge(const struct key_def *first, const struct key_def *second);

/*
 * Check that parts of the key match with the key definition.
 * @param key_def Key definition.
 * @param key MessagePack'ed data for matching.
 * @param part_count Field count in the key.
 * @param allow_nullable True if nullable parts are allowed.
 *
 * @retval 0  The key is valid.
 * @retval -1 The key is invalid.
 */
int
key_validate_parts(const struct key_def *key_def, const char *key,
		   uint32_t part_count, bool allow_nullable);

/**
 * Return true if @a index_def defines a sequential key without
 * holes starting from the first field. In other words, for all
 * key parts index_def->parts[part_id].fieldno == part_id.
 * @param index_def index_def
 * @retval true index_def is sequential
 * @retval false otherwise
 */
static inline bool
key_def_is_sequential(const struct key_def *key_def)
{
	for (uint32_t part_id = 0; part_id < key_def->part_count; part_id++) {
		if (key_def->parts[part_id].fieldno != part_id)
			return false;
	}
	return true;
}

/**
 * Return true if @a key_def defines has fields that requires
 * special collation comparison.
 * @param key_def key_def
 * @retval true if the key_def has collation fields
 * @retval false otherwise
 */
static inline bool
key_def_has_collation(const struct key_def *key_def)
{
	for (uint32_t part_id = 0; part_id < key_def->part_count; part_id++) {
		if (key_def->parts[part_id].coll != NULL)
			return true;
	}
	return false;
}

/** A helper table for key_mp_type_validate */
extern const uint32_t key_mp_type[];

/**
 * @brief Checks if \a field_type (MsgPack) is compatible \a type (KeyDef).
 * @param type KeyDef type
 * @param field_type MsgPack type
 * @param field_no - a field number (is used to store an error message)
 *
 * @retval 0  mp_type is valid.
 * @retval -1 mp_type is invalid.
 */
static inline int
key_mp_type_validate(enum field_type key_type, enum mp_type mp_type,
		     int err, uint32_t field_no, bool is_nullable)
{
	assert(key_type < field_type_MAX);
	assert((size_t) mp_type < CHAR_BIT * sizeof(*key_mp_type));
	uint32_t mask = key_mp_type[key_type] | (is_nullable * (1U << MP_NIL));
	if (unlikely((mask & (1U << mp_type)) == 0)) {
		diag_set(ClientError, err, field_no, field_type_strs[key_type]);
		return -1;
	}
	return 0;
}

/**
 * Compare two key part arrays.
 *
 * One key part is considered to be greater than the other if:
 * - its fieldno is greater
 * - given the same fieldno, NUM < STRING
 *
 * A key part array is considered greater than the other if all
 * its key parts are greater, or, all common key parts are equal
 * but there are additional parts in the bigger array.
 */
int
key_part_cmp(const struct key_part *parts1, uint32_t part_count1,
	     const struct key_part *parts2, uint32_t part_count2);

/**
 * Find out whether alteration of an index has changed it
 * substantially enough to warrant a rebuild or not. For example,
 * change of index id is not a substantial change, whereas change
 * of index type or incompatible change of key parts requires
 * a rebuild.
 */
bool
key_part_check_compatibility(const struct key_part *old_parts,
			     uint32_t old_part_count,
			     const struct key_part *new_parts,
			     uint32_t new_part_count);

#if defined(__cplusplus)
} /* extern "C" */
#endif /* defined(__cplusplus) */

#endif /* TARANTOOL_BOX_KEY_DEF_H_INCLUDED */
