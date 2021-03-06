/*
 * Copyright 2010-2017, Tarantool AUTHORS, please see AUTHORS file.
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

/*
 *
 * This file contains code used to implement incremental BLOB I/O.
 */

#include "sqliteInt.h"
#include "vdbeInt.h"
#include "msgpuck/msgpuck.h"
#include "box/session.h"

#ifndef SQLITE_OMIT_INCRBLOB

/*
 * Valid sqlite3_blob* handles point to Incrblob structures.
 */
typedef struct Incrblob Incrblob;
struct Incrblob {
	int flags;		/* Copy of "flags" passed to sqlite3_blob_open() */
	int nByte;		/* Size of open blob, in bytes */
	int iOffset;		/* Byte offset of blob in cursor data */
	int iCol;		/* Table column this handle is open on */
	BtCursor *pCsr;		/* Cursor pointing at blob row */
	sqlite3_stmt *pStmt;	/* Statement holding cursor open */
	sqlite3 *db;		/* The associated database */
	Table *pTab;		/* Table object */
};

/*
 * This function is used by both blob_open() and blob_reopen(). It seeks
 * the b-tree cursor associated with blob handle p to point to row iRow.
 * If successful, SQLITE_OK is returned and subsequent calls to
 * sqlite3_blob_read() or sqlite3_blob_write() access the specified row.
 *
 * If an error occurs, or if the specified row does not exist or does not
 * contain a value of type TEXT or BLOB in the column nominated when the
 * blob handle was opened, then an error code is returned and *pzErr may
 * be set to point to a buffer containing an error message. It is the
 * responsibility of the caller to free the error message buffer using
 * sqlite3DbFree().
 *
 * If an error does occur, then the b-tree cursor is closed. All subsequent
 * calls to sqlite3_blob_read(), blob_write() or blob_reopen() will
 * immediately return SQLITE_ABORT.
 */
static int
blobSeekToRow(Incrblob * p, sqlite3_int64 iRow, char **pzErr)
{
	int rc;			/* Error code */
	char *zErr = 0;		/* Error message */
	Vdbe *v = (Vdbe *) p->pStmt;

	/* Set the value of the SQL statements only variable to integer iRow.
	 * This is done directly instead of using sqlite3_bind_int64() to avoid
	 * triggering asserts related to mutexes.
	 */
	assert(v->aVar[0].flags & MEM_Int);
	v->aVar[0].u.i = iRow;

	rc = sqlite3_step(p->pStmt);
	if (rc == SQLITE_ROW) {
		VdbeCursor *pC = v->apCsr[0];
		u8 buf[8];

		p->pCsr = pC->uc.pCursor;
		sqlite3BtreeIncrblobCursor(p->pCsr);

		rc = sqlite3BtreePayload(pC->uc.pCursor,
					 (u32) p->iOffset,
					 (unsigned int)p->nByte >
					 sizeof(buf) ? sizeof(buf) : (u32) p->
					 nByte, buf);
		if (rc == SQLITE_OK) {
			/* Skip MsgPack header and reject certain types. */
			u8 *zParse = buf;
			switch (mp_typeof(*buf)) {
			default:{
					zErr =
					    sqlite3MPrintf(p->db,
							   "cannot open value of type %s",
							   "FIXME");
					rc = SQLITE_ERROR;
					break;
				}
			case MP_STR:
			case MP_BIN:{
					p->nByte =
					    mp_decode_strbinl((const char **)
							      &zParse);
					p->iOffset = (u32) (zParse - buf);
					break;
				}
			}
		}
	}

	if (rc != SQLITE_OK && p->pStmt) {
		rc = sqlite3_finalize(p->pStmt);
		p->pStmt = 0;
		if (rc == SQLITE_OK) {
			zErr =
			    sqlite3MPrintf(p->db, "no such rowid: %lld", iRow);
			rc = SQLITE_ERROR;
		} else {
			zErr =
			    sqlite3MPrintf(p->db, "%s", sqlite3_errmsg(p->db));
		}
	}

	assert(rc != SQLITE_OK || zErr == 0);
	assert(rc != SQLITE_ROW && rc != SQLITE_DONE);

	*pzErr = zErr;
	return rc;
}

/*
 * Open a blob handle.
 */
int
sqlite3_blob_open(sqlite3 * db,	/* The database connection */
		  const char *zTable,	/* The table containing the blob */
		  const char *zColumn,	/* The column containing the blob */
		  sqlite_int64 iRow,	/* The row containing the glob */
		  int flags,	/* True -> read/write access, false -> read-only */
		  sqlite3_blob ** ppBlob	/* Handle for accessing the blob returned here */
    )
{
	int nAttempt = 0;
	int iCol;		/* Index of zColumn in row-record */
	int rc = SQLITE_OK;
	char *zErr = 0;
	Table *pTab;
	Parse *pParse = 0;
	Incrblob *pBlob = 0;
	struct session *user_session = current_session();

#ifdef SQLITE_ENABLE_API_ARMOR
	if (ppBlob == 0) {
		return SQLITE_MISUSE_BKPT;
	}
#endif
	*ppBlob = 0;
#ifdef SQLITE_ENABLE_API_ARMOR
	if (!sqlite3SafetyCheckOk(db) || zTable == 0) {
		return SQLITE_MISUSE_BKPT;
	}
#endif
	flags = ! !flags;	/* flags = (flags ? 1 : 0); */

	sqlite3_mutex_enter(db->mutex);

	pBlob = (Incrblob *) sqlite3DbMallocZero(db, sizeof(Incrblob));
	if (!pBlob)
		goto blob_open_out;
	pParse = sqlite3StackAllocRaw(db, sizeof(*pParse));
	if (!pParse)
		goto blob_open_out;

	do {
		memset(pParse, 0, sizeof(Parse));
		pParse->db = db;
		sqlite3DbFree(db, zErr);
		zErr = 0;

		sqlite3BtreeEnterAll(db);
		pTab = sqlite3LocateTable(pParse, 0, zTable);
		if (pTab && !HasRowid(pTab)) {
			pTab = 0;
			sqlite3ErrorMsg(pParse,
					"cannot open table without rowid: %s",
					zTable);
		}
#ifndef SQLITE_OMIT_VIEW
		if (pTab && pTab->pSelect) {
			pTab = 0;
			sqlite3ErrorMsg(pParse, "cannot open view: %s", zTable);
		}
#endif
		if (!pTab) {
			if (pParse->zErrMsg) {
				sqlite3DbFree(db, zErr);
				zErr = pParse->zErrMsg;
				pParse->zErrMsg = 0;
			}
			rc = SQLITE_ERROR;
			sqlite3BtreeLeaveAll(db);
			goto blob_open_out;
		}
		pBlob->pTab = pTab;

		/* Now search pTab for the exact column. */
		for (iCol = 0; iCol < pTab->nCol; iCol++) {
			if (strcmp(pTab->aCol[iCol].zName, zColumn) ==
			    0) {
				break;
			}
		}
		if (iCol == pTab->nCol) {
			sqlite3DbFree(db, zErr);
			zErr =
			    sqlite3MPrintf(db, "no such column: \"%s\"",
					   zColumn);
			rc = SQLITE_ERROR;
			sqlite3BtreeLeaveAll(db);
			goto blob_open_out;
		}

		/* If the value is being opened for writing, check that the
		 * column is not indexed, and that it is not part of a foreign key.
		 * It is against the rules to open a column to which either of these
		 * descriptions applies for writing.
		 */
		if (flags) {
			const char *zFault = 0;
			Index *pIdx;
#ifndef SQLITE_OMIT_FOREIGN_KEY
			if (user_session->sql_flags & SQLITE_ForeignKeys) {
				/* Check that the column is not part of an FK child key definition. It
				 * is not necessary to check if it is part of a parent key, as parent
				 * key columns must be indexed. The check below will pick up this
				 * case.
				 */
				FKey *pFKey;
				for (pFKey = pTab->pFKey; pFKey;
				     pFKey = pFKey->pNextFrom) {
					int j;
					for (j = 0; j < pFKey->nCol; j++) {
						if (pFKey->aCol[j].iFrom ==
						    iCol) {
							zFault = "foreign key";
						}
					}
				}
			}
#endif
			for (pIdx = pTab->pIndex; pIdx; pIdx = pIdx->pNext) {
				int j;
				for (j = 0; j < pIdx->nKeyCol; j++) {
					/* FIXME: Be smarter about indexes that use expressions */
					if (pIdx->aiColumn[j] == iCol
					    || pIdx->aiColumn[j] == XN_EXPR) {
						zFault = "indexed";
					}
				}
			}
			if (zFault) {
				sqlite3DbFree(db, zErr);
				zErr =
				    sqlite3MPrintf(db,
						   "cannot open %s column for writing",
						   zFault);
				rc = SQLITE_ERROR;
				sqlite3BtreeLeaveAll(db);
				goto blob_open_out;
			}
		}

		pBlob->pStmt = (sqlite3_stmt *) sqlite3VdbeCreate(pParse);
		assert(pBlob->pStmt || db->mallocFailed);
		if (pBlob->pStmt) {

			/* This VDBE program seeks a btree cursor to the identified
			 * db/table/row entry. The reason for using a vdbe program instead
			 * of writing code to use the b-tree layer directly is that the
			 * vdbe program will take advantage of the various transaction,
			 * locking and error handling infrastructure built into the vdbe.
			 *
			 * After seeking the cursor, the vdbe executes an OP_ResultRow.
			 * Code external to the Vdbe then "borrows" the b-tree cursor and
			 * uses it to implement the blob_read(), blob_write() and
			 * blob_bytes() functions.
			 *
			 * The sqlite3_blob_close() function finalizes the vdbe program,
			 * which closes the b-tree cursor and (possibly) commits the
			 * transaction.
			 */
			static const int iLn = VDBE_OFFSET_LINENO(2);
			static const VdbeOpList openBlob[] = {
				{OP_TableLock, 0, 0, 0},	/* 0: Acquire a read or write lock */
				{OP_OpenRead, 0, 0, 0},	/* 1: Open a cursor */
				{OP_Variable, 1, 1, 0},	/* 2: Move ?1 into reg[1] */
				{OP_NotExists, 0, 7, 1},	/* 3: Seek the cursor */
				{OP_Column, 0, 0, 1},	/* 4  */
				{OP_ResultRow, 1, 0, 0},	/* 5  */
				{OP_Goto, 0, 2, 0},	/* 6  */
				{OP_Halt, 0, 0, 0},	/* 7  */
			};
			Vdbe *v = (Vdbe *) pBlob->pStmt;
			VdbeOp *aOp;

			sqlite3VdbeAddOp4Int(v, OP_Transaction, 0, flags,
					     pTab->pSchema->schema_cookie,
					     pTab->pSchema->iGeneration);
			sqlite3VdbeChangeP5(v, 1);
			aOp =
			    sqlite3VdbeAddOpList(v, ArraySize(openBlob),
						 openBlob, iLn);

			/* Make sure a mutex is held on the table to be accessed */
			sqlite3VdbeUsesBtree(v);

			if (db->mallocFailed == 0) {
				assert(aOp != 0);
				/* Configure the OP_TableLock instruction */
#ifdef SQLITE_OMIT_SHARED_CACHE
				aOp[0].opcode = OP_Noop;
#else
				aOp[0].p1 = 0;
				aOp[0].p2 = pTab->tnum;
				aOp[0].p3 = flags;
				sqlite3VdbeChangeP4(v, 1, pTab->zName,
						    P4_TRANSIENT);
			}
			if (db->mallocFailed == 0) {
#endif

				/* Remove either the OP_OpenWrite or OpenRead. Set the P2
				 * parameter of the other to pTab->tnum.
				 */
				if (flags)
					aOp[1].opcode = OP_OpenWrite;
				aOp[1].p2 = pTab->tnum;
				aOp[1].p3 = 0;

				/* Configure the number of columns. Configure the cursor to
				 * think that the table has one more column than it really
				 * does. An OP_Column to retrieve this imaginary column will
				 * always return an SQL NULL. This is useful because it means
				 * we can invoke OP_Column to fill in the vdbe cursors type
				 * and offset cache without causing any IO.
				 */
				aOp[1].p4type = P4_INT32;
				aOp[1].p4.i = pTab->nCol + 1;
				aOp[4].p2 = pTab->nCol;

				pParse->nVar = 1;
				pParse->nMem = 1;
				pParse->nTab = 1;
				sqlite3VdbeMakeReady(v, pParse);
			}
		}

		pBlob->flags = flags;
		pBlob->iCol = iCol;
		pBlob->db = db;
		sqlite3BtreeLeaveAll(db);
		if (db->mallocFailed) {
			goto blob_open_out;
		}
		sqlite3_bind_int64(pBlob->pStmt, 1, iRow);
		rc = blobSeekToRow(pBlob, iRow, &zErr);
	} while ((++nAttempt) < SQLITE_MAX_SCHEMA_RETRY && rc == SQLITE_SCHEMA);

 blob_open_out:
	if (rc == SQLITE_OK && db->mallocFailed == 0) {
		*ppBlob = (sqlite3_blob *) pBlob;
	} else {
		if (pBlob && pBlob->pStmt)
			sqlite3VdbeFinalize((Vdbe *) pBlob->pStmt);
		sqlite3DbFree(db, pBlob);
	}
	sqlite3ErrorWithMsg(db, rc, (zErr ? "%s" : 0), zErr);
	sqlite3DbFree(db, zErr);
	sqlite3ParserReset(pParse);
	sqlite3StackFree(db, pParse);
	rc = sqlite3ApiExit(db, rc);
	sqlite3_mutex_leave(db->mutex);
	return rc;
}

/*
 * Close a blob handle that was previously created using
 * sqlite3_blob_open().
 */
int
sqlite3_blob_close(sqlite3_blob * pBlob)
{
	Incrblob *p = (Incrblob *) pBlob;
	int rc;
	sqlite3 *db;

	if (p) {
		db = p->db;
		sqlite3_mutex_enter(db->mutex);
		rc = sqlite3_finalize(p->pStmt);
		sqlite3DbFree(db, p);
		sqlite3_mutex_leave(db->mutex);
	} else {
		rc = SQLITE_OK;
	}
	return rc;
}

/*
 * Perform a read or write operation on a blob
 */
static int
blobReadWrite(sqlite3_blob * pBlob,
	      void *z,
	      int n, int iOffset, int (*xCall) (BtCursor *, u32, u32, void *)
    )
{
	int rc;
	Incrblob *p = (Incrblob *) pBlob;
	Vdbe *v;
	sqlite3 *db;

	if (p == 0)
		return SQLITE_MISUSE_BKPT;
	db = p->db;
	sqlite3_mutex_enter(db->mutex);
	v = (Vdbe *) p->pStmt;

	if (n < 0 || iOffset < 0 || ((sqlite3_int64) iOffset + n) > p->nByte) {
		/* Request is out of range. Return a transient error. */
		rc = SQLITE_ERROR;
	} else if (v == 0) {
		/* If there is no statement handle, then the blob-handle has
		 * already been invalidated. Return SQLITE_ABORT in this case.
		 */
		rc = SQLITE_ABORT;
	} else {
		/* Call either BtreeData() or BtreePutData(). If SQLITE_ABORT is
		 * returned, clean-up the statement handle.
		 */
		assert(db == v->db);
		sqlite3BtreeEnterCursor(p->pCsr);

#ifdef SQLITE_ENABLE_PREUPDATE_HOOK
		if (xCall == sqlite3BtreePutData && db->xPreUpdateCallback) {
			/* If a pre-update hook is registered and this is a write cursor,
			 * invoke it here.
			 *
			 * TODO: The preupdate-hook is passed SQLITE_DELETE, even though this
			 * operation should really be an SQLITE_UPDATE. This is probably
			 * incorrect, but is convenient because at this point the new.* values
			 * are not easily obtainable. And for the sessions module, an
			 * SQLITE_UPDATE where the PK columns do not change is handled in the
			 * same way as an SQLITE_DELETE (the SQLITE_DELETE code is actually
			 * slightly more efficient). Since you cannot write to a PK column
			 * using the incremental-blob API, this works. For the sessions module
			 * anyhow.
			 */
			sqlite3_int64 iKey;
			iKey = sqlite3BtreeIntegerKey(p->pCsr);
			sqlite3VdbePreUpdateHook(v, v->apCsr[0], SQLITE_DELETE,
						 0, p->pTab, iKey, -1);
		}
#endif

		rc = xCall(p->pCsr, iOffset + p->iOffset, n, z);
		sqlite3BtreeLeaveCursor(p->pCsr);
		if (rc == SQLITE_ABORT) {
			sqlite3VdbeFinalize(v);
			p->pStmt = 0;
		} else {
			v->rc = rc;
		}
	}
	sqlite3Error(db, rc);
	rc = sqlite3ApiExit(db, rc);
	sqlite3_mutex_leave(db->mutex);
	return rc;
}

/*
 * Read data from a blob handle.
 */
int
sqlite3_blob_read(sqlite3_blob * pBlob, void *z, int n, int iOffset)
{
	return blobReadWrite(pBlob, z, n, iOffset, sqlite3BtreePayloadChecked);
}

/*
 * Write data to a blob handle.
 */
int
sqlite3_blob_write(sqlite3_blob * pBlob, const void *z, int n, int iOffset)
{
	return blobReadWrite(pBlob, (void *)z, n, iOffset, sqlite3BtreePutData);
}

/*
 * Query a blob handle for the size of the data.
 *
 * The Incrblob.nByte field is fixed for the lifetime of the Incrblob
 * so no mutex is required for access.
 */
int
sqlite3_blob_bytes(sqlite3_blob * pBlob)
{
	Incrblob *p = (Incrblob *) pBlob;
	return (p && p->pStmt) ? p->nByte : 0;
}

/*
 * Move an existing blob handle to point to a different row of the same
 * database table.
 *
 * If an error occurs, or if the specified row does not exist or does not
 * contain a blob or text value, then an error code is returned and the
 * database handle error code and message set. If this happens, then all
 * subsequent calls to sqlite3_blob_xxx() functions (except blob_close())
 * immediately return SQLITE_ABORT.
 */
int
sqlite3_blob_reopen(sqlite3_blob * pBlob, sqlite3_int64 iRow)
{
	int rc;
	Incrblob *p = (Incrblob *) pBlob;
	sqlite3 *db;

	if (p == 0)
		return SQLITE_MISUSE_BKPT;
	db = p->db;
	sqlite3_mutex_enter(db->mutex);

	if (p->pStmt == 0) {
		/* If there is no statement handle, then the blob-handle has
		 * already been invalidated. Return SQLITE_ABORT in this case.
		 */
		rc = SQLITE_ABORT;
	} else {
		char *zErr;
		rc = blobSeekToRow(p, iRow, &zErr);
		if (rc != SQLITE_OK) {
			sqlite3ErrorWithMsg(db, rc, (zErr ? "%s" : 0), zErr);
			sqlite3DbFree(db, zErr);
		}
		assert(rc != SQLITE_SCHEMA);
	}

	rc = sqlite3ApiExit(db, rc);
	assert(rc == SQLITE_OK || p->pStmt == 0);
	sqlite3_mutex_leave(db->mutex);
	return rc;
}

#endif				/* #ifndef SQLITE_OMIT_INCRBLOB */
