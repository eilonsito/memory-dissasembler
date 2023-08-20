local gv = gg.getValues
local sv = gg.setValues
local sf = string.format


-- //Table of operating system ABIs
local _OSABI = {
  "System V",
  "HP-UX",
  "NetBSD",
  "Linux",
  "GNU Hurd",
  "Solaris",
  "AIX",
  "IRIX",
  "FreeBSD",
  "Tru64",
  "Novell Modesto",
  "OpenBSD",
  "OpenVMS",
  "NonStop Kernel",
  "AROS",
  "Fenix OS",
  "CloudABI"
}

 -- // Table of executable types
local _Type = {
  ["0"] = "ET_NONE",
  ["1"] = "ET_REL",
  ["2"] = "ET_EXEC",
  ["3"] = "ET_DYN",
  ["4"] = "ET_CORE",
  ["65024"] = "ET_LOOS",
  ["65279"] = "ET_HIOS",
  ["65280"] = "ET_LOPROC",
  ["65535"] = "ET_HIPROC"
}

 -- // Table of machine types
local _Machine = {
  ["0"] = "No Specific Instruction Set!",
  ["2"] = "SPARC",
  ["3"] = "x86",
  ["8"] = "MIPS",
  ["20"] = "PowerPC",
  ["22"] = "S390",
  ["40"] = "ARM",
  ["42"] = "SuperH",
  ["50"] = "IA-64",
  ["62"] = "x86-64",
  ["183"] = "AArch64",
  ["243"] = "RISC-V"
}

 -- // Table of program header types
local _pHdrType = {
  "PT_NULL",
  "PT_LOAD",
  "PT_DYNAMIC",
  "PT_INTERP",
  "PT_NOTE",
  "PT_SHLIB",
  "PT_PHDR"
}

 -- // Table of dynamic tags
local _DT = {
  "DT_NULL",
  "DT_NEEDED",
  "DT_PLTRELSZ",
  "DT_PLTGOT",
  "DT_HASH",
  "DT_STRTAB",
  "DT_SYMTAB",
  "DT_RELA",
  "DT_RELASZ",
  "DT_RELAENT",
  "DT_STRSZ",
  "DT_SYMENT",
  "DT_INIT",
  "DT_FINI",
  "DT_SONAME",
  "DT_RPATH",
  "DT_SYMBOLIC",
  "DT_REL",
  "DT_RELSZ",
  "DT_RELENT",
  "DT_PLTREL",
  "DT_DEBUG",
  "DT_TEXTREL",
  "DT_JMPREL"
}

 -- // Table of symbol types
local _ST = {
  "STT_NOTYPE",
  "STT_OBJECT",
  "STT_FUNC",
  "STT_SECTION",
  "STT_FILE",
  "STT_COMMON",
  "STT_TLS"
}

local function rwmem(Address, SizeOrBuffer)
  local _rw = {}
  if type(SizeOrBuffer) == "number" then
    for _ = 1, SizeOrBuffer do
      _rw[_] = { address = (Address - 1) + _, flags = gg.TYPE_BYTE }
    end
     local result = ""
    for v, __ in ipairs(gv(_rw)) do
      result = result .. sf("%02X", __.value & 0xFF)
    end
     return result
  end
   local Byte = {}
  SizeOrBuffer:gsub("..", function(x)
    Byte[#Byte + 1] = x
    _rw[#Byte] = { address = (Address - 1) + #Byte, flags = gg.TYPE_BYTE, value = x .. "h" }
  end)
  sv(_rw)
end


local function rdstr(Address, StrSize)
  if StrSize == nil or type(StrSize) ~= "number" then
    StrSize = 128
  end
  local str = ""
  for _ in rwmem(Address, StrSize):gmatch("..") do
    if _ == "00" then
      break 
    end
    str = str .. string.char(tonumber(_, 16))
  end
  return str
end

local function GetLibraryBase(lib)
  for _, __ in pairs(gg.getRangesList(lib)) do
    if __["state"] == "Xa" then
      return __["start"], __["end"]
    end
  end
  return nil
end



local function GetLibInformation(LibName)
  local LibBase = GetLibraryBase(LibName)
  if LibBase ~= nil then
    local _ = gv({
      { address = LibBase, flags = gg.TYPE_DWORD }, -- Magic (A value that identifies the ELF format)
      { address = LibBase + 0x4, flags = gg.TYPE_BYTE }, -- Class (The class (32-bit or 64-bit) of the ELF file)
      { address = LibBase + 0x5, flags = gg.TYPE_BYTE }, -- Data (The byte order of the data in the ELF file)
      { address = LibBase + 0x6, flags = gg.TYPE_BYTE }, -- Version (The version of the ELF file)
      { address = LibBase + 0x7, flags = gg.TYPE_BYTE }, -- OS ABI (The operatin system and ABI specific information)
      { address = LibBase + 0x8, flags = gg.TYPE_BYTE }, -- ABI Version (The version of the ABI)
      -- EI_PAD skipped --
      { address = LibBase + 0x10, flags = gg.TYPE_WORD }, -- Type (Type of the ELF file)
      { address = LibBase + 0x12, flags = gg.TYPE_WORD }, -- Machine
      { address = LibBase + 0x14, flags = gg.TYPE_DWORD }, -- Version
      { address = LibBase + 0x18, flags = gg.TYPE_DWORD }, -- Entry Point
      { address = LibBase + 0x1C, flags = gg.TYPE_DWORD }, -- Program Header Table (PH) Offset (The offset of the program header table in the ELF file)
      { address = LibBase + 0x20, flags = gg.TYPE_DWORD }, -- Section Header Offset
      { address = LibBase + 0x24, flags = gg.TYPE_DWORD }, -- Flags
      { address = LibBase + 0x28, flags = gg.TYPE_WORD }, -- Elf Header Size
      { address = LibBase + 0x2A, flags = gg.TYPE_WORD }, -- Program Header Table (PH) Size Entry
      { address = LibBase + 0x2C, flags = gg.TYPE_WORD }, -- Number Of Entries In Program Header Table (PH)
      { address = LibBase + 0x2E, flags = gg.TYPE_WORD }, -- Size Of Section Header Table Entry
      { address = LibBase + 0x30, flags = gg.TYPE_WORD }, -- Number of Entries In Section Header Table
      { address = LibBase + 0x32, flags = gg.TYPE_WORD }, -- Section Header String Index
    })


    local Elf = {
      Magic = _[1].value, -- Magic number
      Class = _[2].value, -- ELF class (32-bit or 64-bit)
      Data = _[3].value, -- Data encoding (little endian or big endian)
      Version = _[4].value, -- ELF version
      OSABI = _[5].value, -- OS-specific ABI
      ABIVer = _[6].value, -- ABI version
      Type = _[7].value, -- Object file type
      Machine = _[8].value, -- Target machine architecture
      Version2 = _[9].value, -- ELF version (alternative)
      EntryPoint = _[10].value, -- Entry point virtual address
      PHOffset = _[11].value, -- Offset of the program header table
      PHSize = _[15].value, -- Size of each program header entry
      PHNum = _[16].value, -- Number of program header entries
      SHOffset = _[12].value, -- Offset of the section header table
      SHSize = _[17].value, -- Size of each section header entry
      SHNum = _[18].value, -- Number of section header entries
      SHStrIndex = _[19].value, -- Index of the section header string table
      Flags = _[13].value, -- Processor-specific flags
      HeaderSize = _[14].value, -- Size of the ELF header
      pHdr = {}, -- Program header table
      Dyn = {}, -- Dynamic section table
      Sym = {} -- Symbol table
    }

-- // Parsing Program Header
    for _ = 1, Elf.PHNum do
      local _pHdr = LibBase + Elf.PHOffset + (_ * Elf.PHSize)
      local pHdr = gv({
        { address = _pHdr, flags = gg.TYPE_DWORD }, -- p_type
        { address = _pHdr + 4, flags = gg.TYPE_DWORD }, -- p_offset
        { address = _pHdr + 8, flags = gg.TYPE_DWORD }, -- p_vaddr
        { address = _pHdr + 0xC, flags = gg.TYPE_DWORD }, -- p_paddr
        { address = _pHdr + 0x10, flags = gg.TYPE_DWORD }, -- p_filesz
        { address = _pHdr + 0x14, flags = gg.TYPE_DWORD }, -- p_memsz
        { address = _pHdr + 0x18, flags = gg.TYPE_DWORD }, -- p_flags
        { address = _pHdr + 0x1C, flags = gg.TYPE_DWORD }, -- p_align
      })
      Elf.pHdr[_] = { -- All data in Program Header now in Elf.pHdr[Elf.PHNum]
        p_type = pHdr[1].value,
        p_offset = pHdr[2].value,
        p_vaddr = pHdr[3].value,
        p_paddr = pHdr[4].value,
        p_filesz = pHdr[5].value,
        p_memsz = pHdr[6].value,
        p_flags = pHdr[7].value,
        p_align = pHdr[8].value
      }
    end

-- // Parsing Dynamic Segment
    for _ = 1, Elf.PHNum do
      if _pHdrType[Elf.pHdr[_].p_type + 1] == "PT_DYNAMIC" then
        local DynCount = 0
        while true do
          local _Dyn = gv({
            { address = LibBase + Elf.pHdr[_].p_vaddr + (DynCount * 8), flags = gg.TYPE_DWORD }, -- d_tag
            { address = LibBase + Elf.pHdr[_].p_vaddr + 4 + (DynCount * 8), flags = gg.TYPE_DWORD } -- d_ptr / d_val
          })
          if _Dyn[1].value == 0 and _Dyn[2].value == 0 then
            break
          end -- End of dynamic segment
          DynCount = DynCount + 1 -- Keep growing
          Elf.Dyn[DynCount] = { -- All data in Dynamic Segment now in Elf.Dyn[Section]
            d_tag = _Dyn[1].value,
            d_val = _Dyn[2].value,
            d_ptr = _Dyn[2].value
          }
        end
      end
    end

    --------------- -- Parsing symbol -- ---------------
    local nChain, strtab, symtab
    for _ = 1, #Elf.Dyn do
      if _DT[tonumber(Elf.Dyn[_].d_tag) + 1] == "DT_HASH" then
        nChain = gv({{ address = (Elf.Dyn[_].d_ptr + 4) + LibBase, flags = gg.TYPE_DWORD }})[1].value
      end
      if _DT[tonumber(Elf.Dyn[_].d_tag) + 1] == "DT_STRTAB" then
        strtab = Elf.Dyn[_].d_ptr + LibBase
      end
      if _DT[tonumber(Elf.Dyn[_].d_tag) + 1] == "DT_SYMTAB" then
        symtab = Elf.Dyn[_].d_ptr + LibBase
      end
    end
    if nChain ~= nil then
      for _ = 1, nChain do
        local sym = symtab + (_ * 0x10)
        local __ = gv({
          { address = sym, flags = gg.TYPE_DWORD }, -- st_name
          { address = sym + 0x4, flags = gg.TYPE_DWORD }, -- st_value
          { address = sym + 0x8, flags = gg.TYPE_DWORD }, -- st_size
          { address = sym + 0xC, flags = gg.TYPE_DWORD } -- st_info
        })
        Elf.Sym[_] = {
          name = rdstr(strtab + __[1].value),
          st_name = __[1].value,
          st_value = __[2].value,
          st_size = __[3].value,
          st_info = __[4].value
        }
      end
    end
    return Elf
  end
  return nil
end

------------------------------------------------------------------
-- // #3
------------------------------------------------------------------

if gg.isVisible(true) then
  gg.setVisible(false)
end

local ElfInsideMem = {}
for _, __ in pairs(gg.getRangesList("*.so")) do
  if __["state"] == "Xa" then
    ElfInsideMem[#ElfInsideMem + 1] = __["name"]:match("[^/]+$")
  end
end

local choice = gg.choice(ElfInsideMem, nil, "Please select the library:")
if choice == nil then
  return nil
end

gg.alert("Getting information, Please wait >.<...")
local TargetLib = ElfInsideMem[choice]
local LibBase = GetLibraryBase(TargetLib)
local Elf = GetLibInformation(TargetLib) -- This is where it parses elf data

------------------------------------------------------------------
-- // #4
------------------------------------------------------------------

local SymInfoChooser = {}
for i = 1, #Elf.Sym do
  SymInfoChooser[#SymInfoChooser + 1] = "[" .. tostring(i) .. "]: " .. Elf.Sym[i].name
end

local SymInfoValue = {}
for i = 2, #Elf.Sym do
  SymInfoValue[#SymInfoValue + 1] = "[" .. tostring(i) .. "]: " .. Elf.Sym[i].st_size
end

for i = 1, #Elf.Sym do
  if print(sf("#%d : %s\nOFFSET: 0x%08X", i, Elf.Sym[i].name, Elf.Sym[i].st_value), "     ") == 1 then
  end
end

if gg.alert("Sucessfully Completed", "Ok") == 1 then
  os.exit(gg.setVisible(true))
end
