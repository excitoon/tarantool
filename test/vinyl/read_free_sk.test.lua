--
-- gh-2129: This issue introduces a new type of a vinyl space
-- with read-free REPLACE and DELETE. A vinyl space becames
-- read-free, if it contains only not unique secondary indexes.
-- In such a case garbage collection is deferred until primary
-- index compaction or dump.
--

env = require('test_run')
test_run = env.new()
test_run:cmd("setopt delimiter ';'")

function get_disk_stat(index)
	local info = index:info()
	local new = {}
	new.run_count = info.run_count
	new.disk_rows = info.disk.rows
	new.disk_read_rows = info.disk.iterator.read.rows
	return {new = new, get = get_disk_stat, index = index}
end;

function show_stat_update(stat)
	stat.old = stat.new
	stat.new = stat.get(stat.index).new
	local ret = ''
	for k, v in pairs(stat.new) do
		local diff = stat.new[k] - stat.old[k]
		if diff ~= 0 then
			ret = ret..k..' change = '..diff..'; '
		end
	end
	if ret == '' then
		return 'no changes'
	else
		return ret
	end
end;

function get_cache_stat(index)
	local new = {}
	local info = index:info()
	new.cache_invalidated = info.cache.invalidate.rows
	new.cache_size = info.cache.rows
	new.cache_lookup = info.cache.lookup
	return {new = new, get = get_cache_stat, index = index}
end;

function get_mem_stat(index)
	local new = {}
	local info = index:info()
	new.mem_size = info.memory.rows
	new.mem_lookup = info.memory.iterator.lookup
	return {new = new, get = get_mem_stat, index = index}
end;

test_run:cmd("setopt delimiter ''");

s = box.schema.create_space('test', {engine = 'vinyl'})
pk = s:create_index('pk', {run_count_per_level = 100})
sk = s:create_index('sk', {parts = {2, 'unsigned'}, unique = false, run_count_per_level = 100})

sk_disk_stat = get_disk_stat(sk)
pk_disk_stat = get_disk_stat(pk)

s:replace{1, 20}
s:replace{1, 30}
s:replace{1, 60}
s:replace{1, 50}
s:replace{1, 40}

show_stat_update(sk_disk_stat)
show_stat_update(pk_disk_stat)

sk:select{50}
sk:select{40}

box.snapshot()

-- Sk contains 5 replaces in a one run and 4 deletes in another.
show_stat_update(sk_disk_stat)
show_stat_update(pk_disk_stat)

s:select{}
sk:select{20}
sk:select{30}
sk:select{60}
sk:select{50}
sk:select{40}

show_stat_update(sk_disk_stat)
show_stat_update(pk_disk_stat)

--
-- Ensure a secondary index cache do not return dirty tuples.
--
s:replace{2, 20}
s:replace{2, 30}
sk:select{30}
s:replace{2, 40}
sk:select{30} -- Must not be found.
sk:select{40} -- Found.

--
-- Check DELETE to be read-free.
--
pk:delete{1}
sk:select{40} -- Must return only {2, 40}.

--
-- Check optimized update works correctly.
--
s:replace{3, 10}
s:replace{3, 20}
s:update({3}, {{'!', 3, 300}}) -- Optimized update.
s:select{3}
sk:select{10}
sk:select{20}

--
-- Check that dirty statements are deleted on lookup from a cache
-- sequence of a secondary index.
--
cache_stat = get_cache_stat(sk)

s:replace{4, 1}
s:replace{5, 2}
s:replace{6, 3}
s:replace{7, 4}
s:replace{8, 5}
s:replace{9, 5}
s:replace{10, 4}
s:replace{11, 3}
s:replace{12, 6}
show_stat_update(cache_stat)

sk:select{}
show_stat_update(cache_stat)

mem_stat = get_mem_stat(sk)

s:replace{6, 30}
s:replace{9, 50}
s:replace{11, 30}
show_stat_update(mem_stat)

sk:select{}
show_stat_update(cache_stat)

s:drop()

--
-- Test deleruns generation and compaction.
--

s = box.schema.create_space('test', {engine = 'vinyl'})
pk = s:create_index('pk', {run_count_per_level = 2})
sk = s:create_index('sk', {unique = false, parts = {2, 'unsigned'}, run_count_per_level = 2})

s:replace{5, 1}
s:replace{5, 2}
s:replace{5, 3}
s:replace{5, 6}
s:replace{5, 5}
s:replace{5, 4}

s:replace{6, 7}
s:replace{6, 8}

pk_mem_stat = get_mem_stat(pk)
sk_mem_stat = get_mem_stat(sk)
pk_disk_stat = get_disk_stat(pk)
sk_disk_stat = get_disk_stat(sk)

box.snapshot()

-- Primary has one dumped run and no mems.
show_stat_update(pk_mem_stat)

-- Secondary has two runs: one dumped and one is delerun from pk.
-- Mem is empty too.
show_stat_update(sk_mem_stat)

show_stat_update(pk_disk_stat)

-- 14 disk tuples = 8 replaces + 6 deletes of old versions.
show_stat_update(sk_disk_stat)

-- No old versions skipping.
s:delete{6}
s:replace{6, 9}
s:replace{7, 10}

-- 2 tuples in sk mem: delete is wrote in pk only.
show_stat_update(sk_mem_stat)
show_stat_update(pk_mem_stat)

box.snapshot()

show_stat_update(sk_mem_stat)
show_stat_update(sk_disk_stat)
show_stat_update(pk_mem_stat)
show_stat_update(pk_disk_stat)

s:replace{8, 11}
s:replace{8, 12}
box.snapshot()

show_stat_update(sk_mem_stat)
show_stat_update(sk_disk_stat)
show_stat_update(pk_mem_stat)
show_stat_update(pk_disk_stat)
sk:info().run_count

s:replace{8, 11}
s:replace{8, 12}
box.snapshot()

show_stat_update(sk_mem_stat)
show_stat_update(sk_disk_stat)
show_stat_update(pk_mem_stat)
show_stat_update(pk_disk_stat)

sk_disk_stat.new
pk_disk_stat.new

sk:select{}

--
-- Check deletion of an old verion from a write set of a secondary
-- index.
--
box.begin()
s:replace{9, 100}
s:replace{9, 101}
pk:select{9}
sk:select{9}
box.commit()
pk:select{9}
sk:select{9}

s:drop()
