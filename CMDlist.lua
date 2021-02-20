script_name('CMDlist')
script_author("dmitriyewich")
script_description("With this simple script, when opening the chat input, it will show the custom and all available commands")
script_url("https://vk.com/dmitriyewichmods")
script_dependencies("ffi","encoding", "mimgui", "vkeys", "ziplib", "lfs")
script_properties('work-in-pause')
script_version("2.8")
script_version_number(28)

require "moonloader"
local dlstatus = require "moonloader".download_status
local limgui, imgui = pcall(require, 'mimgui') -- https://github.com/THE-FYP/mimgui
local lencoding, encoding = pcall(require, 'encoding') assert(lencoding, 'Library \'encoding\' not found.')
local lffi, ffi = pcall(require, 'ffi') assert(lffi, 'Library \'ffi\' not found.')
local lvkeys, vkeys = pcall(require, 'vkeys') assert(lvkeys, 'Library \'vkeys\' not found.')
local llfs, lfs = pcall(require, 'lfs')
local lziplib, ziplib = pcall(ffi.load, string.format("%s/lib/ziplib.dll",getWorkingDirectory())) 

local user32 = ffi.load("USER32")
local kernel32 = ffi.load("KERNEL32")

encoding.default = 'CP1251'
u8 = encoding.UTF8
CP1251 = encoding.CP1251

local new, str, sizeof = imgui.new, ffi.string, ffi.sizeof

local function isarray(t, emptyIsObject)
	if type(t)~='table' then return false end
	if not next(t) then return not emptyIsObject end
	local len = #t
	for k,_ in pairs(t) do
		if type(k)~='number' then
			return false
		else
			local _,frac = math.modf(k)
			if frac~=0 or k<1 or k>len then
				return false
			end
		end
	end
	return true
end

local function map(t,f)
	local r={}
	for i,v in ipairs(t) do r[i]=f(v) end
	return r
end

local keywords = {["and"]=1,["break"]=1,["do"]=1,["else"]=1,["elseif"]=1,["end"]=1,["false"]=1,["for"]=1,["function"]=1,["goto"]=1,["if"]=1,["in"]=1,["local"]=1,["nil"]=1,["not"]=1,["or"]=1,["repeat"]=1,["return"]=1,["then"]=1,["true"]=1,["until"]=1,["while"]=1}

local function neatJSON(value, opts) -- https://github.com/Phrogz/NeatJSON/blob/master/lua/neatjson.lua
	opts = opts or {}
	if opts.wrap==nil  then opts.wrap = 80 end
	if opts.wrap==true then opts.wrap = -1 end
	opts.indent         = opts.indent         or "  "
	opts.arrayPadding  = opts.arrayPadding  or opts.padding      or 0
	opts.objectPadding = opts.objectPadding or opts.padding      or 0
	opts.afterComma    = opts.afterComma    or opts.aroundComma  or 0
	opts.beforeComma   = opts.beforeComma   or opts.aroundComma  or 0
	opts.beforeColon   = opts.beforeColon   or opts.aroundColon  or 0
	opts.afterColon    = opts.afterColon    or opts.aroundColon  or 0
	opts.beforeColon1  = opts.beforeColon1  or opts.aroundColon1 or opts.beforeColon or 0
	opts.afterColon1   = opts.afterColon1   or opts.aroundColon1 or opts.afterColon  or 0
	opts.beforeColonN  = opts.beforeColonN  or opts.aroundColonN or opts.beforeColon or 0
	opts.afterColonN   = opts.afterColonN   or opts.aroundColonN or opts.afterColon  or 0

	local colon  = opts.lua and '=' or ':'
	local array  = opts.lua and {'{','}'} or {'[',']'}
	local apad   = string.rep(' ', opts.arrayPadding)
	local opad   = string.rep(' ', opts.objectPadding)
	local comma  = string.rep(' ',opts.beforeComma)..','..string.rep(' ',opts.afterComma)
	local colon1 = string.rep(' ',opts.beforeColon1)..colon..string.rep(' ',opts.afterColon1)
	local colonN = string.rep(' ',opts.beforeColonN)..colon..string.rep(' ',opts.afterColonN)

	local build
	local function rawBuild(o,indent)
		if o==nil then
			return indent..'null'
		else
			local kind = type(o)
			if kind=='number' then
				local _,frac = math.modf(o)
				return indent .. string.format( frac~=0 and opts.decimals and ('%.'..opts.decimals..'f') or '%g', o)
			elseif kind=='boolean' or kind=='nil' then
				return indent..tostring(o)
			elseif kind=='string' then
				return indent..string.format('%q', o):gsub('\\\n','\\n')
			elseif isarray(o, opts.emptyTablesAreObjects) then
				if #o==0 then return indent..array[1]..array[2] end
				local pieces = map(o, function(v) return build(v,'') end)
				local oneLine = indent..array[1]..apad..table.concat(pieces,comma)..apad..array[2]
				if opts.wrap==false or #oneLine<=opts.wrap then return oneLine end
				if opts.short then
					local indent2 = indent..' '..apad;
					pieces = map(o, function(v) return build(v,indent2) end)
					pieces[1] = pieces[1]:gsub(indent2,indent..array[1]..apad, 1)
					pieces[#pieces] = pieces[#pieces]..apad..array[2]
					return table.concat(pieces, ',\n')
				else
					local indent2 = indent..opts.indent
					return indent..array[1]..'\n'..table.concat(map(o, function(v) return build(v,indent2) end), ',\n')..'\n'..(opts.indentLast and indent2 or indent)..array[2]
				end
			elseif kind=='table' then
				if not next(o) then return indent..'{}' end

				local sortedKV = {}
				local sort = opts.sort or opts.sorted
				for k,v in pairs(o) do
					local kind = type(k)
					if kind=='string' or kind=='number' then
						sortedKV[#sortedKV+1] = {k,v}
						if sort==true then
							sortedKV[#sortedKV][3] = tostring(k)
						elseif type(sort)=='function' then
							sortedKV[#sortedKV][3] = sort(k,v,o)
						end
					end
				end
				if sort then table.sort(sortedKV, function(a,b) return a[3]<b[3] end) end
				local keyvals
				if opts.lua then
					keyvals=map(sortedKV, function(kv)
						if type(kv[1])=='string' and not keywords[kv[1]] and string.match(kv[1],'^[%a_][%w_]*$') then
							return string.format('%s%s%s',kv[1],colon1,build(kv[2],''))
						else
							return string.format('[%q]%s%s',kv[1],colon1,build(kv[2],''))
						end
					end)
				else
					keyvals=map(sortedKV, function(kv) return string.format('%q%s%s',kv[1],colon1,build(kv[2],'')) end)
				end
				keyvals=table.concat(keyvals, comma)
				local oneLine = indent.."{"..opad..keyvals..opad.."}"
				if opts.wrap==false or #oneLine<opts.wrap then return oneLine end
				if opts.short then
					keyvals = map(sortedKV, function(kv) return {indent..' '..opad..string.format('%q',kv[1]), kv[2]} end)
					keyvals[1][1] = keyvals[1][1]:gsub(indent..' ', indent..'{', 1)
					if opts.aligned then
						local longest = math.max(table.unpack(map(keyvals, function(kv) return #kv[1] end)))
						local padrt   = '%-'..longest..'s'
						for _,kv in ipairs(keyvals) do kv[1] = padrt:format(kv[1]) end
					end
					for i,kv in ipairs(keyvals) do
						local k,v = kv[1], kv[2]
						local indent2 = string.rep(' ',#(k..colonN))
						local oneLine = k..colonN..build(v,'')
						if opts.wrap==false or #oneLine<=opts.wrap or not v or type(v)~='table' then
							keyvals[i] = oneLine
						else
							keyvals[i] = k..colonN..build(v,indent2):gsub('^%s+','',1)
						end
					end
					return table.concat(keyvals, ',\n')..opad..'}'
				else
					local keyvals
					if opts.lua then
						keyvals=map(sortedKV, function(kv)
							if type(kv[1])=='string' and not keywords[kv[1]] and string.match(kv[1],'^[%a_][%w_]*$') then
								return {table.concat{indent,opts.indent,kv[1]}, kv[2]}
							else
								return {string.format('%s%s[%q]',indent,opts.indent,kv[1]), kv[2]}
							end
						end)
					else
						keyvals = {}
						for i,kv in ipairs(sortedKV) do
							keyvals[i] = {indent..opts.indent..string.format('%q',kv[1]), kv[2]}
						end
					end
					if opts.aligned then
						local longest = math.max(table.unpack(map(keyvals, function(kv) return #kv[1] end)))
						local padrt   = '%-'..longest..'s'
						for _,kv in ipairs(keyvals) do kv[1] = padrt:format(kv[1]) end
					end
					local indent2 = indent..opts.indent
					for i,kv in ipairs(keyvals) do
						local k,v = kv[1], kv[2]
						local oneLine = k..colonN..build(v,'')
						if opts.wrap==false or #oneLine<=opts.wrap or not v or type(v)~='table' then
							keyvals[i] = oneLine
						else
							keyvals[i] = k..colonN..build(v,indent2):gsub('^%s+','',1)
						end
					end
					return indent..'{\n'..table.concat(keyvals, ',\n')..'\n'..(opts.indentLast and indent2 or indent)..'}'
				end
			end
		end
	end

	local function memoize()
		local memo = setmetatable({},{_mode='k'})
		return function(o,indent)
			if o==nil then
				return indent..(opts.lua and 'nil' or 'null')
			elseif o~=o then 
				return indent..(opts.lua and '0/0' or '"NaN"')
			elseif o==math.huge then
				return indent..(opts.lua and '1/0' or '9e9999')
			elseif o==-math.huge then
				return indent..(opts.lua and '-1/0' or '-9e9999')
			end
			local byIndent = memo[o]
			if not byIndent then
				byIndent = setmetatable({},{_mode='k'})
				memo[o] = byIndent
			end
			if not byIndent[indent] then
				byIndent[indent] = rawBuild(o,indent)
			end
			return byIndent[indent]
		end
	end

	build = memoize()
	return build(value,'')
end


ffi.cdef[[
	typedef void *PVOID;
	typedef uint8_t BYTE;
	typedef uint16_t WORD;
	typedef uint32_t DWORD;
	typedef char CHAR;
	typedef CHAR *PCHAR;

	typedef void(__thiscall *HOOK_DIALOG)(PVOID this, WORD wID, BYTE iStyle, PCHAR szCaption, PCHAR szText, PCHAR szButton1, PCHAR szButton2, bool bSend);
	int GetLocaleInfoA(int Locale, int LCType, PCHAR lpLCData, int cchData);
	bool GetKeyboardLayoutNameA(char* pwszKLID);

    intptr_t LoadKeyboardLayoutA(const char* pwszKLID, unsigned int Flags);
    int PostMessageA(intptr_t hWnd, unsigned int Msg, unsigned int wParam, long lParam);
    intptr_t GetActiveWindow();
	
	int zip_extract(const char *zipname, const char *dir,int *func, void *arg);

	enum { CF_TEXT = 1 };
	enum { GMEM_MOVEABLE = 2 };
	int      OpenClipboard(void*);
	void*    GetClipboardData(unsigned);
	int      CloseClipboard();
	int      SetClipboardData(int, void*);
	int      EmptyClipboard();
	void*    memcpy(void*, void*, int);
	void*    GlobalAlloc(int, int);
	void*    GlobalLock(void*);
	int      GlobalUnlock(void*);
	size_t   GlobalSize(void*);
	bool SetCursorPos(int X, int Y);
]]

get = function ()
	local ok1 = user32.OpenClipboard(nil)
	local handle = user32.GetClipboardData(user32.CF_TEXT)
	local size = kernel32.GlobalSize(handle)
	local mem = kernel32.GlobalLock(handle)
	local text = ffi.string(mem, size)
	local ok2 = kernel32.GlobalUnlock(handle)
	local ok3 = user32.CloseClipboard()
	
	return text
end

put = function (text)
	local text_len = #text + 1
	local hMem = kernel32.GlobalAlloc(user32.GMEM_MOVEABLE, text_len)

	ffi.copy(kernel32.GlobalLock(hMem), text, text_len)
	kernel32.GlobalUnlock(hMem)
	user32.OpenClipboard(nil)
	user32.EmptyClipboard()
	user32.SetClipboardData(user32.CF_TEXT, hMem)
	user32.CloseClipboard()
end

do
	local buffer = {}
	function setKeyboardLanguage(lang) -- by RTD
		if buffer[lang] == nil then
			buffer[lang] = ffi.C.LoadKeyboardLayoutA(lang, 1);
		end
		ffi.C.PostMessageA(ffi.C.GetActiveWindow(), 0x50, 1, buffer[lang]);
	end
end

local layout = ffi.new('char[10]')
local info = ffi.new('char[10]')

function getLayoutName()
    ffi.C.GetKeyboardLayoutNameA(layout)
    ffi.C.GetLocaleInfoA(tonumber(ffi.string(layout), 16), 0x3, info, ffi.sizeof(info))
    local res = ffi.string(info):sub(1, 2)
    return res
end

function savejson(table, path)
    local f = io.open(path, "w")
    f:write(table)
    f:close()
end
function convertTableToJsonString(config)
    return (neatJSON(config, {sort = true, wrap = 280, beforeComma = 1}))
end 	
config = {}

if doesFileExist("moonloader/config/CMDlist.json") then
    local f = io.open("moonloader/config/CMDlist.json")
    config = decodeJson(f:read("*a"))
    f:close()
else
   config = {
        ["CMDserver"] = {
            {'time', 'Показывает время'},
			{'mm', 'Игровое меню'},
			{'stats', 'Статистика игрока'};
        },
        ["ConsoleCMD"] = {
			{'test', 'Какой-то текст'},
			{'test2', 'Какой-то текст'};
        }		
	}
    savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")
end

local russian_characters = {
  [168] = 'Ё', [184] = 'ё', [192] = 'А', [193] = 'Б', [194] = 'В', [195] = 'Г', [196] = 'Д', [197] = 'Е', [198] = 'Ж', [199] = 'З', [200] = 'И', [201] = 'Й', [202] = 'К', [203] = 'Л', [204] = 'М', [205] = 'Н', [206] = 'О', [207] = 'П', [208] = 'Р', [209] = 'С', [210] = 'Т', [211] = 'У', [212] = 'Ф', [213] = 'Х', [214] = 'Ц', [215] = 'Ч', [216] = 'Ш', [217] = 'Щ', [218] = 'Ъ', [219] = 'Ы', [220] = 'Ь', [221] = 'Э', [222] = 'Ю', [223] = 'Я', [224] = 'а', [225] = 'б', [226] = 'в', [227] = 'г', [228] = 'д', [229] = 'е', [230] = 'ж', [231] = 'з', [232] = 'и', [233] = 'й', [234] = 'к', [235] = 'л', [236] = 'м', [237] = 'н', [238] = 'о', [239] = 'п', [240] = 'р', [241] = 'с', [242] = 'т', [243] = 'у', [244] = 'ф', [245] = 'х', [246] = 'ц', [247] = 'ч', [248] = 'ш', [249] = 'щ', [250] = 'ъ', [251] = 'ы', [252] = 'ь', [253] = 'э', [254] = 'ю', [255] = 'я',
}

-- http://mydc.ru/ptopic334.html 
function string.rlower(s)
  s = s:lower()
  local strlen = s:len()
  if strlen == 0 then return s end
  s = s:lower()
  local output = ''
  for i = 1, strlen do
    local ch = s:byte(i)
    if ch >= 192 and ch <= 223 then
      output = output .. russian_characters[ch + 32]
    elseif ch == 168 then
      output = output .. russian_characters[184]
    else
      output = output .. string.char(ch)
    end
  end
  return output
end

function string.rupper(s)
  s = s:upper()
  local strlen = s:len()
  if strlen == 0 then return s end
  s = s:upper()
  local output = ''
  for i = 1, strlen do
    local ch = s:byte(i)
    if ch >= 224 and ch <= 255 then
      output = output .. russian_characters[ch - 32]
    elseif ch == 184 then
      output = output .. russian_characters[168]
    else
      output = output .. string.char(ch)
    end
  end
  return output
end

function iPattern(pattern, brackets)
    ('sanity check'):find(pattern)
    local tmp = {}
    local i=1
    while i <= #pattern do              -- 'for' don't let change counter
        local char = pattern:sub(i,i)   -- current char
        if char == '%' then
            tmp[#tmp+1] = char          -- add to tmp table
            i=i+1                       -- next char position
            char = pattern:sub(i,i)
            tmp[#tmp+1] = char
            if char == 'b' then         -- '%bxy' - add next 2 chars
                tmp[#tmp+1] = pattern:sub(i+1,i+2)
                i=i+2
            end
        elseif char=='[' then           -- brackets
            tmp[#tmp+1] = char
            i = i+1
            while i <= #pattern do
                char = pattern:sub(i,i)
                if char == '%' then     -- no '%bxy' inside brackets
                    tmp[#tmp+1] = char
                    tmp[#tmp+1] = pattern:sub(i+1,i+1)
                    i = i+1
                elseif char:match("%W") or char:match("%w") then    -- letter
                    tmp[#tmp+1] = not brackets and char or string.rlower(char), string.rupper(char) -- char:lower()..char:upper()
                else                            -- something else
                    tmp[#tmp+1] = char
                end
                if char==']' then break end -- close bracket
                i = i+1
            end
        elseif char:match("%W") or char:match("%w") then    -- letter
            tmp[#tmp+1] = '['..string.rlower(char)..string.rupper(char)..']' -- '['..char:lower()..char:upper()..']'
        else
            tmp[#tmp+1] = char          -- something else
        end
        i=i+1
    end
    return table.concat(tmp)
end

_png0 ="\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52\x00\x00\x00\x20\x00\x00\x00\x20\x08\x06\x00\x00\x00\x73\x7A\x7A\xF4\x00\x00\x01\x24\x69\x43\x43\x50\x49\x43\x43\x20\x70\x72\x6F\x66\x69\x6C\x65\x00\x00\x28\x91\x63\x60\x60\x32\x70\x74\x71\x72\x65\x12\x60\x60\xC8\xCD\x2B\x29\x0A\x72\x77\x52\x88\x88\x8C\x52\x60\x3F\xCF\xC0\xC6\xC0\xCC\x00\x06\x89\xC9\xC5\x05\x8E\x01\x01\x3E\x20\x76\x5E\x7E\x5E\x2A\x03\x06\xF8\x76\x8D\x81\x11\x44\x5F\xD6\x05\x99\x85\x29\x8F\x17\x70\x25\x17\x14\x95\x00\xE9\x3F\x40\x6C\x94\x92\x5A\x9C\xCC\xC0\xC0\x68\x00\x64\x67\x97\x97\x14\x00\xC5\x19\xE7\x00\xD9\x22\x49\xD9\x60\xF6\x06\x10\xBB\x28\x24\xC8\x19\xC8\x3E\x02\x64\xF3\xA5\x43\xD8\x57\x40\xEC\x24\x08\xFB\x09\x88\x5D\x04\xF4\x04\x90\xFD\x05\xA4\x3E\x1D\xCC\x66\xE2\x00\x9B\x03\x61\xCB\x80\xD8\x25\xA9\x15\x20\x7B\x19\x9C\xF3\x0B\x2A\x8B\x32\xD3\x33\x4A\x14\x0C\x2D\x2D\x2D\x15\x1C\x53\xF2\x93\x52\x15\x82\x2B\x8B\x4B\x52\x73\x8B\x15\x3C\xF3\x92\xF3\x8B\x0A\xF2\x8B\x12\x4B\x52\x53\x80\x6A\x21\xEE\x03\x03\x41\x88\x42\x50\x88\x69\x00\x35\x5A\x68\x92\xE8\x6F\x82\x00\x14\x0F\x10\xD6\xE7\x40\x70\xF8\x32\x8A\x9D\x41\x88\x21\x40\x72\x69\x51\x19\x94\xC9\xC8\x64\x4C\x98\x8F\x30\x63\x8E\x04\x03\x83\xFF\x52\x06\x06\x96\x3F\x08\x31\x93\x5E\x06\x86\x05\x3A\x0C\x0C\xFC\x53\x11\x62\x6A\x86\x0C\x0C\x02\xFA\x0C\x0C\xFB\xE6\x00\x00\xC0\xC6\x4F\xFD\x4E\x62\x34\xD5\x00\x00\x00\x09\x70\x48\x59\x73\x00\x00\x0B\x12\x00\x00\x0B\x12\x01\xD2\xDD\x7E\xFC\x00\x00\x07\x17\x49\x44\x41\x54\x58\x85\xA5\x57\x5D\x4C\x54\xDB\x15\xFE\xF6\xCF\x99\xE1\x0C\x5C\xC7\x0A\x82\x46\x44\xBC\xD7\xDB\xDC\xF8\x13\x2B\xB1\x48\x6A\x5F\x94\xA0\xB9\xC9\x4D\x04\x69\x43\x63\x0C\xC6\x44\x7D\x30\x86\xC4\xC4\x3E\x34\xDE\x3E\xB4\x57\x5B\xE3\x4F\x13\xD1\x66\x12\x35\x8D\x17\xEB\x4F\x62\xED\x0B\xFE\xC0\xF5\x1A\x5A\x1E\xB8\xF1\xD2\x87\x72\x23\x5A\xD4\xC4\x9F\x06\x13\xCE\x30\x03\xC3\x9C\x99\x61\xCE\xD9\xFB\xAC\x3E\x70\x06\x11\x11\x87\xBA\x93\xF3\x70\x76\xD6\xDE\xFB\x5B\xDF\x5A\x7B\xAD\x6F\xB3\x1D\x3B\x76\xE0\xD5\xAB\x57\x30\x0C\x03\x44\x84\x7C\x86\x10\x82\xC7\xE3\x71\x6F\xF7\xEE\xDD\x7F\x1A\x1C\x1C\x1C\xB9\x7B\xF7\xEE\x57\x0B\x16\x2C\x10\x4A\x29\x9D\xD7\x06\x00\x88\x08\x05\x05\x05\x40\x45\x45\x05\x00\x80\x31\x96\xD7\x42\xCE\xB9\x04\x80\xF5\xEB\xD7\x1F\x1A\x1E\x1E\xA6\xBE\xBE\x3E\x2A\x2B\x2B\xDB\xED\xEF\x21\xF3\x05\x00\x00\xA6\x69\x02\x95\x95\x95\x39\xAF\xC0\x39\x9F\xF5\x93\x52\x4A\x00\x28\x2F\x2F\xFF\xFC\xC5\x8B\x17\x64\xDB\xB6\x52\x4A\x79\xDD\xDD\xDD\xD9\x40\x20\xF0\x33\xCE\x39\x84\x10\xE2\x7D\xFB\x70\xCE\x01\x00\x85\x85\x85\xF9\x33\xC0\x18\xE3\x8C\x31\x18\x86\xF1\x49\x47\x47\xC7\x90\xEB\xBA\x64\x59\x96\x67\x59\x96\x26\x22\x6A\x6D\x6D\x7D\x0A\xA0\x4C\x08\x01\x00\x3C\x6F\x06\xF2\x04\xC0\xFC\x8D\x43\x67\xCE\x9C\xE9\x25\x22\x1A\x1A\x1A\x52\xF1\x78\x9C\xE2\xF1\x38\x59\x96\xE5\x12\x11\xED\xDF\xBF\xFF\x2E\x00\x2E\xA5\x64\x00\xDE\x1B\xD3\xBC\x01\x08\x21\x18\x00\xEC\xDD\xBB\xF7\x6B\xCF\xF3\xC8\xB2\x2C\x37\x77\x78\x3C\x1E\xA7\x58\x2C\x46\xF1\x78\xDC\x4D\xA5\x52\xB4\x69\xD3\xA6\xD3\x00\xC0\x73\x3C\x7F\x28\x00\xCE\xB9\x00\x80\x8D\x1B\x37\x1E\x8C\xC7\xE3\x14\x8D\x46\x9D\xE1\xE1\x61\x9A\x0A\xC0\x67\x81\x46\x47\x47\xDD\x27\x4F\x9E\xD0\x92\x25\x4B\x72\x49\x29\x3E\x14\x00\xF7\xE7\x4B\xBB\xBB\xBB\x13\x44\x44\x4A\x29\xCF\xB6\xED\x9C\xD7\x93\x0C\x64\x32\x19\x72\x1C\xC7\x23\x22\xBA\x70\xE1\x42\x14\x40\xB1\x9F\xB3\xEF\x64\xC2\x34\x4D\x88\x70\x38\x8C\x44\x22\xF1\x16\x00\xCE\xB9\x60\x8C\x91\x10\x42\x78\x9E\x67\x3F\x7D\xFA\x74\x31\x11\xFD\xA4\xA7\xA7\xC7\x2E\x2A\x2A\x32\x4A\x4B\x4B\xB9\x52\x0A\x00\x10\x0C\x06\xD1\xDB\xDB\xAB\xDB\xDB\xDB\xC7\x06\x06\x06\xF8\xA5\x4B\x97\x7A\x9E\x3F\x7F\xFE\x97\x5C\x14\x18\x63\x82\x66\x28\x32\x86\x61\xCC\xC8\x00\x13\x7E\xC6\x01\x28\x9A\xE2\x01\x17\x42\x94\x01\x28\x8B\x44\x22\xFD\x7E\x2E\xE8\xDC\x2D\x38\x70\xE0\xC0\xBF\x01\x2C\x94\x52\x2E\x01\x60\xFA\x6B\x24\x80\x8F\x18\x63\xF0\xF7\x7C\xC3\x4B\xD3\x34\xDF\xA4\x87\x31\xC6\xA5\x94\x5C\x6B\xAD\x6B\x6A\x6A\xF6\xDF\xBB\x77\x6F\xA8\xBE\xBE\x3E\x02\x00\x52\x4A\x26\xA5\xB4\x00\x0C\x71\xCE\x5D\x22\xCA\x81\x26\x9F\x31\x07\x40\x54\x08\xF1\xCA\x30\x0C\x17\x00\xEA\xEB\xEB\x7F\xDF\xD1\xD1\x11\xAD\xAC\xAC\x6C\xD6\x5A\x6B\x29\x25\x9F\x1E\x92\xC9\x1F\xCE\xB9\xE0\x9C\x7B\x4A\x29\xB6\x73\xE7\xCE\x73\xB7\x6F\xDF\xFE\xF3\xE6\xCD\x9B\x43\x7B\xF6\xEC\x69\x06\xF0\xB1\x10\x42\xFB\x1E\x61\x9A\x27\x2C\x07\x3E\x47\x37\xE7\x9C\x00\xA0\xA1\xA1\xE1\x8B\xAD\x5B\xB7\x06\xBB\xBA\xBA\xBE\xAE\xAB\xAB\x3B\xAD\x94\x22\x29\x25\xE5\x12\x7B\x2A\x00\x49\x44\x9A\x88\x16\x1F\x3B\x76\xEC\x9F\x6D\x6D\x6D\x7B\x3D\xCF\x73\xC7\xC7\xC7\x61\xDB\x36\x01\x20\xD7\x75\xA1\xB5\xD6\x00\xE0\x79\x1E\x31\xC6\x72\xBD\x83\x00\x40\x6B\xED\x01\x80\x52\x4A\x2B\xA5\x3C\x00\x48\xA7\xD3\x9E\xE3\x38\x08\x87\xC3\xD9\xF6\xF6\xF6\x96\x96\x96\x96\x6F\x94\x52\xC5\x8C\xB1\x49\x67\xA4\x10\x42\x02\x50\x25\x25\x25\x3F\x3F\x77\xEE\xDC\xB5\x6D\xDB\xB6\x2D\x19\x1E\x1E\x56\x8C\x31\x43\x29\x85\x35\x6B\xD6\x04\x4F\x9D\x3A\x75\xCD\x30\x8C\x34\x00\x91\xCD\x66\xBD\xEA\xEA\xEA\x15\xE9\x74\x1A\x42\x08\x46\x44\x2C\x9D\x4E\xA3\xBE\xBE\xFE\xB3\x8A\x8A\x8A\x7F\x98\xA6\xC9\x88\x08\xD9\x6C\x96\xAA\xAB\xAB\x57\xB8\xAE\x0B\xA5\x54\x20\x95\x4A\xA9\xD3\xA7\x4F\xD7\xAE\x5C\xB9\xF2\xFB\x83\x07\x0F\xFE\x2A\x93\xC9\x7C\xCF\x39\x97\x58\xB4\x68\x11\x56\xAD\x5A\xB5\xF7\xF1\xE3\xC7\x5A\x6B\xFD\x46\x85\x8B\xC5\x62\x34\x36\x36\x46\x44\x44\x9E\xE7\x91\xE7\x79\x44\x44\xF4\xAE\x6B\x38\x9B\x5D\x2C\x16\x23\xCB\xB2\x14\x11\x51\x4F\x4F\x8F\x53\x5E\x5E\xDE\x2C\xA5\x04\xDB\xB7\x6F\xDF\x57\x47\x8E\x1C\xF9\xB2\xB0\xB0\x50\xA7\x52\x29\xE6\x27\xCA\xE4\x20\xA2\x49\xEA\x73\x43\x08\xC1\xD9\xB4\x7B\xEB\x1F\xEC\xBD\xCF\xCE\x75\x5D\x2F\x1C\x0E\xC3\xB2\x2C\xDE\xD4\xD4\xF4\x3B\x9E\x4A\xA5\x8A\x6C\xDB\x86\x94\x72\x36\x31\xC0\x66\xF8\xF2\xB1\x99\xD1\x4E\x08\xA1\x93\xC9\x24\xB2\xD9\xEC\x0A\x2C\x5E\xBC\x18\x4B\x97\x2E\xFD\x75\x6F\x6F\x2F\x11\x91\x67\x59\xD6\x1B\x21\x48\x26\x93\x34\x7D\xCC\x16\x82\x77\xD9\xC5\x62\x31\x8A\x46\xA3\x9A\x88\x74\x67\x67\x27\x95\x94\x94\x1C\x37\x0C\x03\x6C\xF9\xF2\xE5\xE2\xD9\xB3\x67\xBA\xA8\xA8\xE8\x8B\xB3\x67\xCF\xB6\xED\xDA\xB5\xEB\x47\xB1\x58\x4C\x11\x91\x0C\x85\x42\x18\x18\x18\xA0\x2B\x57\xAE\xBC\x0C\x04\x02\x2E\x63\x8C\x65\x32\x19\x6C\xDF\xBE\x7D\x69\x55\x55\x55\x20\x9D\x4E\x03\x00\x42\xA1\x10\x3A\x3B\x3B\xB3\xDD\xDD\xDD\xFF\x0D\x85\x42\x0C\x00\x32\x99\x0C\x1A\x1B\x1B\x97\xAE\x5B\xB7\x2E\x60\xDB\x36\x0C\xC3\xD0\xE1\x70\x58\x9C\x38\x71\x22\x73\xF8\xF0\xE1\xFD\x4A\xA9\x8B\x85\x85\x85\x3C\x57\x09\xA5\x5F\xFC\x7E\x7C\xE8\xD0\xA1\x3E\xC7\x71\x68\x64\x64\xC4\xC9\x64\x32\x74\xF5\xEA\xD5\x34\x80\x4F\x7D\x41\x52\x00\x40\x44\x22\x91\x1F\x66\xA8\x84\xFF\xC2\x44\x2B\x0E\x0A\x21\x02\x00\x64\x24\x12\xE9\x1B\x1F\x1F\xA7\x44\x22\x91\x1D\x1B\x1B\xA3\xE6\xE6\xE6\x67\x00\x7E\xEA\xF7\x08\x69\x9A\x26\xCB\x25\x9C\x22\x22\x29\xA5\x7C\x7C\xF2\xE4\xC9\x8D\x0D\x0D\x0D\x7F\x4B\xA5\x52\x46\x41\x41\x01\xE6\xCD\x9B\x27\x01\x78\x86\x61\x40\x08\xE1\x00\xD0\x42\x4C\x94\xF6\xA9\xF9\x25\x84\x20\x00\x9E\x94\xD2\x31\x0C\xC3\x01\xA0\x4C\xD3\x64\xC1\x60\x10\x83\x83\x83\x81\xBA\xBA\xBA\x6F\xDB\xDA\xDA\x36\x48\x29\x7B\xB5\xD6\x12\x80\x02\x40\x93\x19\x4F\x44\x4A\x6B\xCD\xA5\x94\xE9\x5B\xB7\x6E\xFD\x72\xCB\x96\x2D\x5F\xDE\xB8\x71\x03\xAD\xAD\xAD\xDF\x01\x18\xD2\x5A\xB3\x29\xB6\x6F\x65\x56\x6E\x8E\x88\xA0\x94\x0A\x00\xC0\xE5\xCB\x97\xBF\xBD\x76\xED\x1A\x6A\x6B\x6B\x4F\xDE\xBF\x7F\xFF\x73\x29\xA5\xA5\x94\x12\x44\xA4\x26\x17\xBE\xA3\x19\xE5\xDA\xF0\xC7\x00\x0A\xA7\xCC\x03\x00\x22\x91\x48\xDF\x0C\x21\xE8\x05\x26\x7A\xC6\x94\xEC\x0F\x02\xF8\x94\x31\xC6\x39\xE7\x0C\xD3\xFA\x80\x69\x9A\x60\x15\x15\x15\x78\xF9\xF2\x25\xA6\x94\x56\x00\x98\x58\xC1\x98\x66\x8C\x71\xA5\x94\xD7\xD8\xD8\xF8\x87\xA6\xA6\xA6\x5F\x24\x93\xC9\xF4\x86\x0D\x1B\x3E\x5B\xB6\x6C\x59\xD0\x71\x1C\x00\x40\x20\x10\xC0\x83\x07\x0F\x32\xFD\xFD\xFD\xFF\x99\x3F\x7F\xFE\x47\x17\x2F\x5E\xBC\x73\xF3\xE6\xCD\x16\x29\x25\x9F\xA8\x4D\x1E\xF7\xDB\x31\x4D\x07\xF0\x3E\x41\x22\x72\x82\xA4\xAB\xAB\x2B\x41\x44\xE4\x38\x8E\x97\x4C\x26\xDF\xBA\x86\xE9\x74\x9A\xC6\xC7\xC7\x3D\x22\xA2\xF3\xE7\xCF\x8F\x00\x28\xF5\x19\x7B\xA7\x2A\x9A\x93\x24\x5B\xBD\x7A\xF5\x6F\x86\x86\x86\x28\x16\x8B\x65\xA3\xD1\xE8\x8C\x92\x6C\x6C\x6C\x2C\xFB\xF0\xE1\x43\x5A\xB8\x70\xE1\x1F\xFD\x3D\x67\xD5\x85\x73\x16\xA5\x4D\x4D\x4D\xD7\x5D\xD7\xA5\x68\x34\xFA\x96\x28\x1D\x19\x19\x51\xA3\xA3\xA3\x54\x53\x53\x73\x1B\xAF\x35\xE9\xAC\xCA\x78\x4E\xB2\xDC\xBF\xBB\xF3\x8E\x1E\x3D\xFA\xC3\x74\x59\x1E\x8D\x46\xB5\xD6\x9A\x9A\x9B\x9B\x07\x30\xA1\x8A\x80\x3C\xDE\x06\x73\x01\x90\x13\x1A\x00\xB0\xFA\xFA\xF5\xEB\x71\xAD\x75\xEE\x61\xE2\x11\x11\x1D\x3F\x7E\xDC\xC6\xEB\x22\x33\xAB\x1A\xFE\xBF\x00\x00\xAF\xDF\x85\xC5\xC5\xC5\xDB\xFB\xFB\xFB\xC9\xB6\x6D\xE5\xBA\xAE\xBA\x73\xE7\x0E\x71\xCE\x9B\x19\x63\x73\x7A\x1F\xCE\x19\x00\x00\xF8\x02\x06\x6B\xD7\xAE\xFD\x6D\x22\x91\xA0\x47\x8F\x1E\x51\x69\x69\xE9\x31\x1F\x60\x5E\x9E\x7F\x10\x00\x1F\x04\x07\x80\xDA\xDA\xDA\xBF\x56\x55\x55\xFD\x7D\xE2\x6C\x9E\xD7\x73\x6C\x3A\x80\xFF\x01\x50\x04\x9C\xDB\x5B\x7C\x08\x37\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82"

if limgui then
	main_Window, CMDserver_window_state, posrenderWindow = new.bool(), new.bool(), new.bool()
	local sizeX, sizeY = getScreenResolution()
	ConsoleCMD_window_state, ConsoleCMDedit_window_state = new.bool(), new.bool()
	console_button = imgui.new.bool(false)
	console_button_text = 'Раскрыть'
	imgui.OnInitialize(function()
		apply_custom_style()
		-- imgui.GetIO().IniFilename = nil
		png0 = imgui.CreateTextureFromFileInMemory(_png0, #_png0)
	end)
	ConsoleCMDtext = ''
	local anchor ={}
	
	function imgui.Hint(text, delay)
		if imgui.IsItemHovered() then
			if go_hint == nil then go_hint = os.clock() + (delay and delay or 0.0) end
			local alpha = (os.clock() - go_hint) * 3.5
			if os.clock() >= go_hint then
				imgui.PushStyleVarFloat(imgui.StyleVar.Alpha, (alpha <= 1.0 and alpha or 1.0))
					imgui.BeginTooltip()
					imgui.PushTextWrapPos(450)
						imgui.TextUnformatted(text)
					if not imgui.IsItemVisible() and imgui.GetStyle().Alpha == 1.0 then go_hint = nil end
					imgui.PopTextWrapPos()
					imgui.EndTooltip()
				imgui.PopStyleVar()
			end
		end
	end
	
	function imgui.ButtonDisabled(...)
		imgui.PushStyleColor(imgui.Col.Button, imgui.ImVec4(0.10, 0.10, 0.10, 0.00) )
		imgui.PushStyleColor(imgui.Col.ButtonHovered, imgui.ImVec4(0.10, 0.10, 0.10, 0.00))
		imgui.PushStyleColor(imgui.Col.ButtonActive, imgui.ImVec4(0.10, 0.10, 0.10, 0.00))
		imgui.PushStyleColor(imgui.Col.Text, imgui.GetStyle().Colors[imgui.Col.TextDisabled])
			local result = imgui.Button(...)
		imgui.PopStyleColor(4)
		return result
	end
		end_main_window = 100
	local newFrame = imgui.OnFrame(
		function() return main_Window[0] end,
		function(one)
			imgui.PushStyleColor(imgui.Col.WindowBg, imgui.ImVec4(0.0, 0.0, 0.0, 0.35))
			imgui.PushStyleColor(imgui.Col.Border, imgui.ImVec4(0.0, 0.0, 0.0, 0.05))
			imgui.SetNextWindowPos(imgui.ImVec2(sizeX / 4.1, sizeY / 1.85), imgui.Cond.FirstUseEver, imgui.ImVec2(0.5, 0.5))
			-- if not console_button[0] then
				imgui.SetNextWindowSize(imgui.ImVec2(574, end_main_window), imgui.Cond.Always)
			-- else
				-- imgui.SetNextWindowSize(imgui.ImVec2(574, 300), imgui.Cond.Always)
			-- end
			if posrenderWindow[0] then
			imgui.Begin("cmd", main_Window, imgui.WindowFlags.NoScrollbar + imgui.WindowFlags.NoCollapse + imgui.WindowFlags.NoResize + imgui.WindowFlags.NoTitleBar)
			elseif not posrenderWindow[0] then
			imgui.Begin("cmd", main_Window, imgui.WindowFlags.NoScrollbar + imgui.WindowFlags.NoCollapse + imgui.WindowFlags.NoResize + imgui.WindowFlags.NoMove + imgui.WindowFlags.NoTitleBar)
			end
			-- one.HideCursor = true
			imgui.TextColoredRGB("Пользовательские команды")
			if imgui.IsItemHovered() then
				if go_CMDserver == nil then go_CMDserver = os.clock() + (0.55 and 0.55 or 0.0) end
				local alpha = (os.clock() - go_CMDserver) * 3.5
				if os.clock() >= go_CMDserver then
					imgui.PushStyleVarFloat(imgui.StyleVar.Alpha, (alpha <= 1.0 and alpha or 1.0))
						imgui.BeginTooltip()
						imgui.PushTextWrapPos(450)
							imgui.TextUnformatted('Чтобы добавить команду нажмите "+" возле этого текста\nНажмите СКМ чтобы выполнить сортировку команд\nНажмите СКМ по команде, чтобы изменить ёё')
						if not imgui.IsItemVisible() and imgui.GetStyle().Alpha == 1.0 then go_CMDserver = nil end
						imgui.PopTextWrapPos()
						imgui.EndTooltip()
					imgui.PopStyleVar()
				end
			end
			if not imgui.IsItemHovered() then go_CMDserver = nil end
			if not imgui.IsAnyItemHovered() and imgui.GetStyle().Alpha == 1.0 then go_hint = nil end
			imgui.PushStyleColor(imgui.Col.Button, imgui.ImVec4(0.15, 0.15, 0.15, 0.45))			
			if imgui.BeginPopupContextItem("##sort1", 2) then
				imgui.SetCursorPosX(imgui.GetWindowWidth()/2 - imgui.CalcTextSize("Сортировка").x / 2)
				imgui.Text("Сортировка")
				if imgui.Button( "От А до Я##", imgui.ImVec2(170, 20)) then
					table.sort(config.CMDserver, function(a, b) return a[1] < b[1] end)
					savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")
					imgui.CloseCurrentPopup()
				end
				if imgui.Button( "От Я до А", imgui.ImVec2(170, 20)) then
				table.sort(config.CMDserver, function(a, b) return a[1] > b[1] end)
				savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")
				imgui.CloseCurrentPopup()
				end
				imgui.EndPopup()
			end
			imgui.PopStyleColor()			
			imgui.SameLine()
			if imgui.Button("+##1", imgui.ImVec2(0, 0)) then
			CMDserver_window_state[0] = not CMDserver_window_state[0]
			ConsoleCMD_window_state[0] = false
			ConsoleCMDedit_window_state[0] = false
			end
		
			imgui.SameLine()
			if posrenderWindow[0] then
			imgui.PushStyleVarFloat(imgui.StyleVar.Alpha, 1.0)
			else
			imgui.PushStyleVarFloat(imgui.StyleVar.Alpha, 0.3)
			end
			imgui.SetCursorPosY(imgui.GetCursorPosY() - 3)		
			imgui.SetCursorPosX(imgui.GetWindowWidth() - 34)	
			if imgui.ImageButton(png0, imgui.ImVec2(20, 20)) then
				posrenderWindow[0] = not posrenderWindow[0]
			end					
			imgui.PopStyleVar()		
			imgui.Hint('Активация флага перемещения окна с командами\nПеремещайте само окно, а не кнопку\nПозиция сохраняется отдельным файлом в по пути config\\mimgui', 0.55)
			imgui.NewLine()
			imgui.SetCursorPosY(imgui.GetCursorPosY() - 25)
			local ChatInputText = sampGetChatInputText()
			for q, w in pairs(config.CMDserver) do 
				local CMDserverCmd, CMDserverDescription = unpack(config.CMDserver[q])
				if CMDserverCmd:find(string.gsub(iPattern(string.gsub(ChatInputText, '[%/%.%@%!%#%%%^%&%*%-%+]', '', 1)), '%[%s%s%]', '.+')) then
					if imgui.Button(""..(CMDserverCmd), imgui.ImVec2(0, 0)) then
						sampProcessChatInput('/'..CMDserverCmd)
					end
					if imgui.IsItemClicked(1) then
						sampSetChatInputText('/'..CMDserverCmd..' ')
					end
					if imgui.IsItemClicked(2) then
					CMDserver_window_state[0] = true
					ConsoleCMD_window_state[0] = false
					ConsoleCMDedit_window_state[0] = false
						CMDserverbuf = new.char[128](''..(CMDserverCmd))
						CMDserverbuff = imgui.new.char[256](''..(CMDserverDescription))
					end			
					imgui.Hint(''.. (CMDserverDescription), 0.55)
					if imgui.BeginDragDropSource() then
						anchor.data = ffi.new("int[1]",tonumber(q))
						imgui.SetDragDropPayload("ITEMN",anchor.data, ffi.sizeof"int")--, C.ImGuiCond_Once);
						imgui.Button(""..(CMDserverCmd), imgui.ImVec2(0,0));
						imgui.EndDragDropSource();
					end
					if imgui.BeginDragDropTarget() then
						local payload = imgui.AcceptDragDropPayload("ITEMN")
						if (payload~=nil) then
								assert(payload.DataSize == ffi.sizeof"int");
							local num = ffi.cast("int*",payload.Data)[0]
							local tmp = config.CMDserver[num]
							table.remove(config.CMDserver,num)
							table.insert(config.CMDserver, q ,tmp)
							savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")
						end
						imgui.EndDragDropTarget();
					end
				else 
					imgui.ButtonDisabled(""..(CMDserverCmd), imgui.ImVec2(0, 0))		
				end
				if ((((q)-1) % 9) < 8) then imgui.SameLine() end
			end
			imgui.Text('')
			if imgui.SelectButton(''..console_button_text, console_button, imgui.ImVec2(574, 0)) then
				if console_button[0] then
					console_button_text = 'Скрыть'
				else
					console_button_text = 'Раскрыть'

				end 
			end
			if console_button[0] then
			imgui.SetCursorPosY(imgui.GetCursorPosY() + 2)
			imgui.TextColoredRGB("Команды с консоли(chatcmds)")
			if imgui.IsItemHovered() then
				if go_ConsoleCMD == nil then go_ConsoleCMD = os.clock() + (0.55 and 0.55 or 0.0) end
				local alpha = (os.clock() - go_ConsoleCMD) * 3.5
				if os.clock() >= go_ConsoleCMD then
					imgui.PushStyleVarFloat(imgui.StyleVar.Alpha, (alpha <= 1.0 and alpha or 1.0))
						imgui.BeginTooltip()
						imgui.PushTextWrapPos(450)
							imgui.TextUnformatted('Чтобы добавить команды нажмите "+" возле этого текста\nНажмите СКМ чтобы выполнить сортировку команд\nНажмите СКМ по команде, чтобы изменить ёё описание')
						if not imgui.IsItemVisible() and imgui.GetStyle().Alpha == 1.0 then go_ConsoleCMD = nil end
						imgui.PopTextWrapPos()
						imgui.EndTooltip()
					imgui.PopStyleVar()
					
				end
			end
			if not imgui.IsItemHovered() then go_ConsoleCMD = nil end
			imgui.PushStyleColor(imgui.Col.Button, imgui.ImVec4(0.15, 0.15, 0.15, 0.45))
			if imgui.BeginPopupContextItem("##sort2", 2) then
				imgui.SetCursorPosX(imgui.GetWindowWidth()/2 - imgui.CalcTextSize("Сортировка").x / 2)
				imgui.Text("Сортировка")
				if imgui.Button( "От А до Я##2", imgui.ImVec2(0, 20)) then
					table.sort(config.ConsoleCMD, function(a, b) return a[1] < b[1] end)
					savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")
					imgui.CloseCurrentPopup()
				end
				if imgui.Button( "От Я до А##2", imgui.ImVec2(0, 20)) then
				table.sort(config.ConsoleCMD, function(a, b) return a[1] > b[1] end)
				savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")
				imgui.CloseCurrentPopup()
				end
				imgui.EndPopup()
			end
			imgui.PopStyleColor()			
			imgui.SameLine()
			if imgui.Button("+##3", imgui.ImVec2(0, 0)) then
				lua_thread.create(function()
					setKeyboardLanguage("00000419") --ru
					wait(74)
					put(u8:decode'Читай инструкцию')
				end)
				CMDserver_window_state[0] = false
				ConsoleCMDedit_window_state[0] = false
				ConsoleCMD_window_state[0] = not ConsoleCMD_window_state[0]
			end

			imgui.SetCursorPosY(imgui.GetCursorPosY() - 5)
			for q, w in pairs(config.ConsoleCMD) do 
				local ConsoleCMDCmd, ConsoleCMDDescription = unpack(config.ConsoleCMD[q])
				if ConsoleCMDCmd:find(string.gsub(iPattern(string.gsub(ChatInputText, '[%/%.%@%!%#%%%^%&%*%-%+]', '', 1)), '%[%s%s%]', '.+')) then
					if imgui.Button(""..(ConsoleCMDCmd), imgui.ImVec2(0, 0)) then
						sampProcessChatInput('/'..ConsoleCMDCmd)
						end
					if imgui.IsItemClicked(1) then
						sampSetChatInputText('/'..ConsoleCMDCmd..' ')
					end
					if imgui.IsItemClicked(2) then
						ConsoleCMDedit_window_state[0] = true
						ConsoleCMD_window_state[0] = false
						CMDserver_window_state[0] = false
						ConsoleCMDtext = ''..(ConsoleCMDCmd)
						ConsoleCMDedit = imgui.new.char[256](''..(ConsoleCMDDescription))
					end			
					if imgui.IsItemHovered() then
						imgui.Hint(''..ConsoleCMDDescription, 0.55)
					end			
					if imgui.BeginDragDropSource() then
						anchor.data = ffi.new("int[1]",tonumber(q))
						imgui.SetDragDropPayload("ITEMN",anchor.data, ffi.sizeof"int")--, C.ImGuiCond_Once);
						imgui.Button(""..(ConsoleCMDCmd), imgui.ImVec2(0,0));
						imgui.EndDragDropSource();
					end
					if imgui.BeginDragDropTarget() then
						local payload = imgui.AcceptDragDropPayload("ITEMN")
						if (payload~=nil) then
							assert(payload.DataSize == ffi.sizeof"int");
							local num = ffi.cast("int*",payload.Data)[0]
							local tmp = config.ConsoleCMD[num]
							table.remove(config.ConsoleCMD,num)
							table.insert(config.ConsoleCMD, q ,tmp)
							savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")
						end
						imgui.EndDragDropTarget();
					end
				else 
					imgui.ButtonDisabled(""..(ConsoleCMDCmd), imgui.ImVec2(0, 0))
				end
				if ((((q)-1) % 9) < 8) then imgui.SameLine() end
			end
			end
			imgui.PopStyleColor(2)	
			imgui.Text('')
			end_main_window = imgui.GetCursorPos().y
			-- print(end_main_window)
			imgui.End()
		end)
		
	CMDserverbuf = new.char[128]('')
	CMDserverbuff = imgui.new.char[256]('')
	imgui.OnFrame(function() return CMDserver_window_state[0] and isSampfuncsLoaded() and isSampLoaded() and not isPauseMenuActive() and sampIsChatVisible() and not sampIsScoreboardOpen() end,
	function(two)
		local sizeX, sizeY = getScreenResolution()
		imgui.SetNextWindowPos(imgui.ImVec2(sizeX / 2, sizeY / 2), imgui.Cond.FirstUseEver, imgui.ImVec2(0.5, 0.5))    
		imgui.SetNextWindowSize(imgui.ImVec2(200, 120), imgui.Cond.FirstUseEver, imgui.NoResize) 
		imgui.Begin('Пользовательские команды##2', CMDserver_window_state, imgui.WindowFlags.NoResize + imgui.WindowFlags.NoCollapse, imgui.WindowFlags.AlwaysUseWindowPadding) --  + imgui.WindowFlags.NoScrollbar
		imgui.SetScrollY(imgui.GetScrollMaxY())
			imgui.PushItemWidth(180)
			imgui.InputTextWithHint('##ID 1', 'Введите команду без /', CMDserverbuf, sizeof(CMDserverbuf), imgui.InputTextFlags.AutoSelectAll)
			imgui.PopItemWidth()
			imgui.PushItemWidth(180)
			imgui.InputTextWithHint('##ID 2', 'Введите описание команды', CMDserverbuff, sizeof(CMDserverbuff), imgui.InputTextFlags.AutoSelectAll)
			imgui.PopItemWidth()
			imgui.SetCursorPosX((imgui.GetWindowWidth() - 140) / 2)
			imgui.PushStyleColor(imgui.Col.Button, imgui.ImVec4(0.10, 0.09, 0.12, 0.65))
			adasdtruethen = true
			if imgui.Button("Сохранить\nкоманду", imgui.ImVec2(70, 35)) then
				for q, w in pairs(config.CMDserver) do
					if config.CMDserver[q][1]:find((str(CMDserverbuf))) then
						config.CMDserver[q] = {(str(CMDserverbuf)), (str(CMDserverbuff))}
						adasdtruethen = false
					end
				end
				if adasdtruethen then
					-- table.insert(config.CMDserver, {(str(CMDserverbuf)), (str(CMDserverbuff))})
					config.CMDserver[#config.CMDserver + 1] = {(str(CMDserverbuf)), (str(CMDserverbuff))}
				end
				savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")
				adasdtruethen = true
			end	
			imgui.PopStyleColor()
			imgui.SameLine()
			imgui.PushStyleColor(imgui.Col.Button, imgui.ImVec4(0.10, 0.09, 0.12, 0.65))
			if imgui.Button("Удалить\nкоманду", imgui.ImVec2(70, 35)) then
			for q, w in pairs(config.CMDserver) do
				for k, v in pairs(config.CMDserver[q]) do
					if (v):find(str(CMDserverbuf)) then
						config.CMDserver[q] = nil
					end
				end
			end
				savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")	
			end
			imgui.PopStyleColor()
		if CMDserver_window_state[0] == false then CMDserverbuf = new.char[128](''); CMDserverbuff = imgui.new.char[256](''); adasdtruethen = true; end
		imgui.End()
	end)

	local buf = imgui.new.char[25600]('')
	imgui.OnFrame(function() return ConsoleCMD_window_state[0] and isSampfuncsLoaded() and isSampLoaded() and not isPauseMenuActive() and sampIsChatVisible() and not sampIsScoreboardOpen() end,
	function(four)
		local sizeX, sizeY = getScreenResolution()
		imgui.SetNextWindowPos(imgui.ImVec2(sizeX / 2, sizeY / 2), imgui.Cond.FirstUseEver, imgui.ImVec2(0.5, 0.5))    
		imgui.SetNextWindowSize(imgui.ImVec2(300, 320), imgui.Cond.FirstUseEver, imgui.NoResize) 
		imgui.Begin('Команды с консоли(chatcmds)', ConsoleCMD_window_state, imgui.WindowFlags.NoResize + imgui.WindowFlags.NoCollapse, imgui.WindowFlags.AlwaysUseWindowPadding) --  + imgui.WindowFlags.NoScrollbar
		buf = imgui.new.char[25600](''..u8(get()))
		if sampIsChatInputActive() then	four.HideCursor = true	else four.HideCursor = false end
		imgui.PushItemWidth(280)
		imgui.InputTextMultiline('##input', buf, ffi.sizeof(buf), imgui.ImVec2(0, 0), imgui.InputTextFlags.AutoSelectAll)
		imgui.PushItemWidth(0)
		imgui.SetCursorPosX((imgui.GetWindowWidth() - 250) / 2)
		imgui.PushStyleColor(imgui.Col.Button, imgui.ImVec4(0.10, 0.09, 0.12, 0.65))
		if imgui.Button("Очистить", imgui.ImVec2(70, 35)) then
			count = #config.ConsoleCMD
			for i=0, count do config.ConsoleCMD[i]=nil end
			savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")
		end
		imgui.Hint('Данная кнопка очищает массив с командами из консоли.', 0.55)
		imgui.SameLine()
		if imgui.Button("Открыть\nконсоль", imgui.ImVec2(90, 35)) then
			if getLayoutName() == 'RU' then
				setKeyboardLanguage("00000409") --en
				sampSetChatInputEnabled(false)
				runSampfuncsConsoleCommand('clear')
				runSampfuncsConsoleCommand('chatcmds')
				lua_thread.create(function()
				wait(74)
				setVirtualKeyDown(vkeys.VK_OEM_3, true)
				setVirtualKeyDown(vkeys.VK_2, true)
				setVirtualKeyDown(vkeys.VK_2, false)
				setVirtualKeyDown(vkeys.VK_OEM_3, false)
				-- setKeyboardLanguage("00000419") --ru
				end)
			elseif getLayoutName() == 'EN' then
				sampSetChatInputEnabled(false)
				runSampfuncsConsoleCommand('clear')
				runSampfuncsConsoleCommand('chatcmds')
				lua_thread.create(function()
				wait(74)
				setVirtualKeyDown(vkeys.VK_OEM_3, true)
				setVirtualKeyDown(vkeys.VK_2, true)
				setVirtualKeyDown(vkeys.VK_2, false)
				setVirtualKeyDown(vkeys.VK_OEM_3, false)
				setKeyboardLanguage("00000419") --ru
				end)		
			end
		end
		imgui.SameLine()
		if imgui.Button("Добавить\nкоманды", imgui.ImVec2(70, 35)) then
		file = io.open('moonloader\\tets.txt', 'w+')
		file:write(''..str(buf))
		file:close()
			lua_thread.create(function()
				wait(274)
					function file_exists(filess)
				  local f = io.open(filess, "rb")
				  if f then f:close() end
				  return f ~= nil
				end


				function lines_from(filess)
				  if not file_exists(filess) then return {} end
				  lines = {}
				  
				  for line in io.lines(filess) do 
					lines[#lines + 1] = line
				  end
				  return lines
				end

				local filess = getGameDirectory()..'\\moonloader\\tets.txt'
				local lines = lines_from(filess)
				
				
				for k,v in pairs(lines) do	
					 if v:find("(.+%w)%s%s---%s%s(.+)%s%W") then
						local nick, description = v:match("(.+%w)%s%s---%s%s(.+)%s%W") 
						config.ConsoleCMD[#config.ConsoleCMD + 1] = {(nick), (description)}
						-- table.sort(config, function(a, b) return a.ConsoleCMD < b.ConsoleCMD end)
						savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")
						os.remove("moonloader/tets.txt")
					end	
				end
						ConsoleCMD_window_state[0] = false
						setVirtualKeyDown(vkeys.VK_OEM_3, true)
						setVirtualKeyDown(vkeys.VK_2, true)
						setVirtualKeyDown(vkeys.VK_2, false)
						setVirtualKeyDown(vkeys.VK_OEM_3, false)
			end)
		end
		imgui.PopStyleColor()
		imgui.TextWrapped('Краткая инструкция.\n1. Нажмите "Очистить"\n2.Нажмите "Открыть консоль"\n3.Скопируйте содержимое консоли(CTRL+A CTRL+C)\n4.Нажмите Добавить команды\n5.Готово')	
		if ConsoleCMD_window_state[0] == false then buf = new.char[25600](''); end
		imgui.End()
	end)

	ConsoleCMDedit = imgui.new.char[256]('')
	imgui.OnFrame(function() return ConsoleCMDedit_window_state[0] and isSampfuncsLoaded() and isSampLoaded() and not isPauseMenuActive() and sampIsChatVisible() and not sampIsScoreboardOpen() end,
	function(five)
		local sizeX, sizeY = getScreenResolution()
		imgui.SetNextWindowPos(imgui.ImVec2(sizeX / 2, sizeY / 2), imgui.Cond.FirstUseEver, imgui.ImVec2(0.5, 0.5))    
		imgui.SetNextWindowSize(imgui.ImVec2(200, 120), imgui.Cond.FirstUseEver, imgui.NoResize) 
		imgui.Begin('Команды с консоли(chatcmds)##2', ConsoleCMDedit_window_state, imgui.WindowFlags.NoResize + imgui.WindowFlags.NoCollapse, imgui.WindowFlags.AlwaysUseWindowPadding) --  + imgui.WindowFlags.NoScrollbar
			imgui.Text('Команда: /'..ConsoleCMDtext)
			imgui.PushItemWidth(180)
			imgui.InputTextWithHint('##ID 4', 'Введите описание команды', ConsoleCMDedit, sizeof(ConsoleCMDedit), imgui.InputTextFlags.AutoSelectAll)
			imgui.PopItemWidth()
			imgui.SetCursorPosX((imgui.GetWindowWidth() - 140) / 2)
			imgui.PushStyleColor(imgui.Col.Button, imgui.ImVec4(0.10, 0.09, 0.12, 0.65))
			if imgui.Button("Сохранить описание", imgui.ImVec2(70, 35)) then
			for q, w in pairs(config.ConsoleCMD) do 
				for k, v in pairs(config.ConsoleCMD[q]) do
					if (v):find(str(ConsoleCMDtext)) then
						config.ConsoleCMD[q] = {(str(ConsoleCMDtext)), (str(ConsoleCMDedit))}
					end	
				end
			end			

				savejson(convertTableToJsonString(config), "moonloader/config/CMDlist.json")	
			end		
			imgui.PopStyleColor()		
		if ConsoleCMDedit_window_state[0] == false then ConsoleCMDtext = ''; ConsoleCMDedit = imgui.new.char[256](''); end
		imgui.End()
	end)

	function imgui.TextColoredRGB(text) -- by #Northn, edited dmitriyewich
		local style = imgui.GetStyle()
		local colors = style.Colors
		local col = imgui.Col

		local designText = function(text__)
			local pos = imgui.GetCursorPos()
			if sampGetChatDisplayMode() == 2 then
				for i = 1, 1 do
					imgui.SetCursorPos(imgui.ImVec2(pos.x + i, pos.y))
					imgui.TextColored(imgui.ImVec4(0, 0, 0, 1), text__)
					imgui.SetCursorPos(imgui.ImVec2(pos.x - i, pos.y))
					imgui.TextColored(imgui.ImVec4(0, 0, 0, 1), text__) 
					imgui.SetCursorPos(imgui.ImVec2(pos.x, pos.y + i))
					imgui.TextColored(imgui.ImVec4(0, 0, 0, 1), text__) 
				end
			end
			imgui.SetCursorPos(pos)
		end

		local color = colors[col.Text]
		local start = 1
		imgui.NewLine()
		if #text >= start then
			imgui.SameLine(nil, 0)
			designText(text:sub(start))			
			imgui.TextColored(color, text:sub(start))
		end
	end
	function imgui.SelectButton(name, bool, size) -- by CaJlaT, eddited dmitriyewich
		if bool[0] then
			imgui.PushStyleColor(imgui.Col.Button, imgui.GetStyle().Colors[imgui.Col.ButtonActive])
			imgui.PushStyleColor(imgui.Col.ButtonHovered, imgui.GetStyle().Colors[imgui.Col.ButtonHovered])
			imgui.PushStyleColor(imgui.Col.ButtonActive, imgui.GetStyle().Colors[imgui.Col.Button])
		else
			imgui.PushStyleColor(imgui.Col.Button, imgui.GetStyle().Colors[imgui.Col.Button])
			imgui.PushStyleColor(imgui.Col.ButtonHovered, imgui.GetStyle().Colors[imgui.Col.ButtonHovered])
			imgui.PushStyleColor(imgui.Col.ButtonActive, imgui.GetStyle().Colors[imgui.Col.ButtonActive])
		end
		if not size then size = imgui.ImVec2(0, 0) end
		local result = imgui.Button(name, size)
		imgui.PopStyleColor(3)
		if result then bool[0] = not bool[0] end
		return result
	end

	function apply_custom_style()					 
		local style = imgui.GetStyle()
		local colors = style.Colors
		local clr = imgui.Col
		local ImVec4 = imgui.ImVec4
		
		colors[clr.Text] = ImVec4(0.90, 0.90, 0.95, 1.00)
		colors[clr.WindowBg] = ImVec4(0.06, 0.05, 0.07, 1.00)
		colors[clr.PopupBg] = ImVec4(0.07, 0.07, 0.09, 1.00)												
		colors[clr.Border] = ImVec4(0.80, 0.80, 0.83, 0.88)
		colors[clr.BorderShadow] = ImVec4(0.92, 0.91, 0.88, 0.00)
		colors[clr.FrameBg] = ImVec4(0.10, 0.09, 0.12, 1.00)
		colors[clr.FrameBgHovered] = ImVec4(0.24, 0.23, 0.29, 1.00)
		colors[clr.FrameBgActive] = ImVec4(0.56, 0.56, 0.58, 1.00)
		colors[clr.TitleBg] = ImVec4(0.10, 0.09, 0.12, 1.00)
		colors[clr.TitleBgActive] = ImVec4(0.07, 0.07, 0.09, 1.00)
		colors[clr.TitleBgCollapsed] = ImVec4(1.00, 0.98, 0.95, 0.75)
		colors[clr.MenuBarBg] = ImVec4(0.10, 0.09, 0.12, 1.00)
		colors[clr.ScrollbarBg] = ImVec4(0.02, 0.02, 0.02, 0.53)
		colors[clr.ScrollbarGrab] = ImVec4(0.80, 0.80, 0.83, 0.31)
		colors[clr.ScrollbarGrabHovered] = ImVec4(0.56, 0.56, 0.58, 1.00)
		colors[clr.ScrollbarGrabActive] = ImVec4(0.06, 0.05, 0.07, 1.00)
		colors[clr.CheckMark] = ImVec4(0.98, 0.26, 0.26, 1.00)
		colors[clr.SliderGrab] = ImVec4(0.28, 0.28, 0.28, 1.00)
		colors[clr.SliderGrabActive] = ImVec4(0.06, 0.05, 0.07, 1.00)
		colors[clr.Button] = ImVec4(0.0, 0.0, 0.0, 0.01)
		colors[clr.ButtonHovered] = ImVec4(0.24, 0.23, 0.29, 1.00)
		colors[clr.ButtonActive] = ImVec4(0.56, 0.56, 0.58, 1.00)	
		colors[clr.Header] = ImVec4(0.10, 0.09, 0.12, 1.00)
		colors[clr.HeaderHovered] = ImVec4(0.56, 0.56, 0.58, 1.000)
		colors[clr.HeaderActive] = ImVec4(0.06, 0.05, 0.07, 1.00)
		colors[clr.Separator] = colors[clr.Border]
		colors[clr.SeparatorHovered] = ImVec4(0.26, 0.59, 0.98, 0.78)
		colors[clr.SeparatorActive] = ImVec4(0.26, 0.59, 0.98, 1.00)
		colors[clr.ResizeGrip] = ImVec4(0.00, 0.00, 0.00, 0.00)
		colors[clr.ResizeGripHovered] = ImVec4(0.56, 0.56, 0.58, 1.00)
		colors[clr.ResizeGripActive] = ImVec4(0.06, 0.05, 0.07, 1.00)
		colors[clr.PlotLines] = ImVec4(0.40, 0.39, 0.38, 0.63)
		colors[clr.PlotLinesHovered] = ImVec4(0.25, 1.00, 0.00, 1.00)
		colors[clr.PlotHistogram] = ImVec4(0.40, 0.39, 0.38, 0.63)
		colors[clr.PlotHistogramHovered] = ImVec4(0.25, 1.00, 0.00, 1.00)
		colors[clr.TextSelectedBg] = ImVec4(0.25, 1.00, 0.00, 0.43)
	end
	

	
end
local active = true
SetCursorPos_active = true
function main()
	if not isSampLoaded() then return end
	while not isSampAvailable() or not isSampfuncsLoaded() do wait(0) end
	checklibs() -- удалить тут
	sampRegisterChatCommand("cmdlist", function() 
		active = not active
		if sampIsChatInputActive() then main_Window[0] = false end
	end)
	sampSetClientCommandDescription("cmdlist", string.format(u8:decode"Активация/деактивация %s, Файл: %s", thisScript().name, thisScript().filename))
	while true do wait(0)
		if active then
			if sampIsChatInputActive() then
				main_Window[0] = true
			else  
				main_Window[0] = false
			end
		end
	end
end

if lziplib then -- отсюда и до конца
	function zipextract(script_name)
		
		file_path = getWorkingDirectory() .. "\\" .. script_name ..".zip"

		if doesFileExist(file_path) then
			print(u8:decode"Распаковка архива: " .. script_name)
			local extract_des = string.format("%s\\%s",getWorkingDirectory(),script_name)
			ziplib.zip_extract(file_path,extract_des,nil,nil)
			MoveFiles(extract_des,getWorkingDirectory().."\\lib")
			os.remove(file_path)
			print(u8:decode"Распаковка прошла успешно, распакован архив: " .. script_name)
		else
			print(u8:decode"Файлы не найдет, перезапустите скрипт.")
		end
	end
end

if llfs then 
	function MoveFiles(main_dir,dest_dir)
		for f in lfs.dir(main_dir) do
			local main_file = main_dir .. "\\" .. f

			if doesDirectoryExist(main_file) and f ~= "." and f ~= ".." then
				MoveFiles(main_file,dest_dir .. "\\" .. f)
			end

			if doesFileExist(main_file) then
				dest_file = dest_dir .. "/" .. f
				if not doesDirectoryExist(dest_dir) then
					lfs.mkdir(dest_dir)
				end
				
				if doesFileExist(dest_file) then
					os.remove(dest_file)
				end
				if doesFileExist(dest_file) then
					os.remove(main_file)
					print(u8:decode"Невозможно удалить файл " .. dest_file)
				else
					os.rename(main_file,dest_file)
				end
				
			end
		end
		lfs.rmdir(main_dir)
	end
end

function checklibs()
	if not limgui or not llfs or not lziplib then	  
		lua_thread.create(function()
			print(u8:decode'Подгрузка необходимых библиотек..')
			if not lziplib then
				downloadFile('ziplib', getWorkingDirectory()..'\\lib\\ziplib.dll', 'https://github.com/dmitriyewich/Personal-Skin-Changer/raw/main/lib/ziplib.dll')
				while not doesFileExist(getWorkingDirectory()..'\\lib\\ziplib.dll') do wait(0) end
				reloadScripts()
			else
				wait(0)
			end
			if not llfs then
				downloadFile('lfs.dll', getWorkingDirectory()..'\\lib\\lfs.dll', 'https://github.com/dmitriyewich/Personal-Skin-Changer/raw/main/lib/lfs.dll')
				while not doesFileExist(getWorkingDirectory()..'\\lib\\lfs.dll') do wait(0) end
				reloadScripts()
			else
				wait(0)
			end
				--mimgui
			if not limgui then
				downloadFile('mimgui-v1.7.0.zip', getWorkingDirectory()..'\\mimgui-v1.7.0.zip', 'https://github.com/THE-FYP/mimgui/releases/download/v1.7.0/mimgui-v1.7.0.zip')
				while not doesFileExist(getWorkingDirectory()..'\\mimgui-v1.7.0.zip') do wait(0) end
				zipextract("mimgui-v1.7.0")
				wait(1000)
				reloadScripts()
			else
				wait(0)
			end
			print(u8:decode'Подгрузка библиотек успешно завершена. Перезагрузка скриптов...')
			wait(1000)
			reloadScripts()
		end)
		return false
	end
	return true
end


function downloadFile(name, path, link)
	if not doesFileExist(path) then
		print('Скачивание файла {006AC2}«'..name..'»')
		downloadUrlToFile(link, path, function(id, status, p1, p2)
			if status == dlstatus.STATUSEX_ENDDOWNLOAD then
				if doesFileExist(path) then
					print(u8:decode'Файл {006AC2}«'..name..u8:decode'»{FFFFFF} загружен!')
				else
					print(u8:decode'Не удалось загрузить файл {006AC2}«'..name..'»')
				end
			end
		end)
	end
end
