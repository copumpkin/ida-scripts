from idaapi import *
from idc import *

def make_structures():
	global objc_class, objc_classinfo, objc_listheader, objc_method, objc_protocol, objc_ivar, objc_property
	
	objc_class = GetStrucIdByName('objc_class')
	objc_classinfo = GetStrucIdByName('objc_classinfo')
	objc_listheader = GetStrucIdByName('objc_listheader')
	objc_method = GetStrucIdByName('objc_method')
	objc_protocol = GetStrucIdByName('objc_protocol')
	objc_ivar = GetStrucIdByName('objc_ivar')
	objc_property = GetStrucIdByName('objc_property')
		
	if objc_class == 4294967295:
		objc_class = AddStruc(-1, 'objc_class')
		AddStrucMember(objc_class, 'metaclass', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_class, 'superclass', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_class, 'cache', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_class, 'vtable', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_class, 'classinfo', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
	
	if objc_classinfo == 4294967295:
		objc_classinfo = AddStruc(-1, 'objc_classinfo')
		AddStrucMember(objc_classinfo, 'version', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_classinfo, 'info', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_classinfo, 'instance_size', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_classinfo, 'unk0', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_classinfo, 'name', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_classinfo, 'methods', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_classinfo, 'protocols', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_classinfo, 'ivars', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_classinfo, 'unk1', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_classinfo, 'properties', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)

	if objc_listheader == 4294967295:
		objc_listheader = AddStruc(-1, 'objc_listheader')
		AddStrucMember(objc_listheader, 'member_size', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_listheader, 'member_count', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)

	if objc_method == 4294967295:
		objc_method = AddStruc(-1, 'objc_method')
		AddStrucMember(objc_method, 'name', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_method, 'type', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_method, 'code', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)

	if objc_protocol == 4294967295:
		objc_protocol = AddStruc(-1, 'objc_protocol')
		AddStrucMember(objc_protocol, 'unk0', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_protocol, 'name', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_protocol, 'unk1', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_protocol, 'methods', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_protocol, 'unk2', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_protocol, 'unk3', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_protocol, 'unk4', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_protocol, 'unk5', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_protocol, 'unk6', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)	

	if objc_ivar == 4294967295:		
		objc_ivar = AddStruc(-1, 'objc_ivar')
		AddStrucMember(objc_ivar, 'offset', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_ivar, 'name', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_ivar, 'type', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_ivar, 'unk0', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)
		AddStrucMember(objc_ivar, 'size', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)	

	if objc_property == 4294967295:	
		objc_property = AddStruc(-1, 'objc_property')
		AddStrucMember(objc_property, 'name', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_property, 'type', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)

def process_list(start_addr, processor):
	if start_addr == 0:
		return
		
	MakeStructEx(start_addr, -1, 'objc_listheader')
	
	member_size  = Dword(start_addr + GetMemberOffset(objc_listheader, 'member_size'))
	member_count = Dword(start_addr + GetMemberOffset(objc_listheader, 'member_count'))
	
	return list(processor(start_addr + 8 + i * member_size) for i in range(member_count))


def make_method(class_name, is_meta, addr):
	MakeStructEx(addr, -1, 'objc_method')
	name_addr = Dword(addr + GetMemberOffset(objc_method, "name"))
	code_addr = Dword(addr + GetMemberOffset(objc_method, "code")) & 0xFFFFFFFE # ignore thumb indicator

	# Add comment to show our knowledge about method
	
	if is_meta:
		MakeNameEx(code_addr, class_name + "_meta " + GetString(name_addr, -1, ASCSTR_C), SN_NOCHECK)
	else:
		MakeNameEx(code_addr, class_name + " " + GetString(name_addr, -1, ASCSTR_C), SN_NOCHECK)

def make_ivar(class_name, is_meta, addr):
	MakeStructEx(addr, -1, 'objc_ivar')
	ivar_name = GetString(Dword(addr + GetMemberOffset(objc_ivar, 'name')), -1, ASCSTR_C)
	type_desc = GetString(Dword(addr + GetMemberOffset(objc_ivar, 'type')), -1, ASCSTR_C)
	size = Dword(addr + GetMemberOffset(objc_ivar, 'size'))
	
	offset_addr = Dword(addr + GetMemberOffset(objc_ivar, 'offset'))
	MakeDword(offset_addr)
	MakeNameEx(offset_addr, 'ivar_' + class_name + '_' + ivar_name, SN_NOCHECK)
	
	return (ivar_name, type_desc, size, Dword(offset_addr))

def make_property(class_name, is_meta, addr):
	MakeStructEx(addr, -1, 'objc_property')

def make_class(addr, is_meta = False):
	if addr == 0:
		return
	
	MakeStructEx(addr, -1, 'objc_class')

	# recursive calls for meta and superclass
	make_class(Dword(addr + GetMemberOffset(objc_class, 'metaclass')), True)	
	make_class(Dword(addr + GetMemberOffset(objc_class, 'superclass')))
	
	# the classinfo is where all the stuff we care about resides
	classinfo_addr = Dword(addr + GetMemberOffset(objc_class, 'classinfo'))
	MakeStructEx(classinfo_addr, -1, 'objc_classinfo')
	
	class_name = GetString(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'name')), -1, ASCSTR_C)
	
	process_list(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'methods'   )), lambda x: make_method(class_name, is_meta, x)) # man, I want partial application...
	ivars = process_list(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'ivars'     )), lambda x: make_ivar(class_name, is_meta, x))
	process_list(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'properties')), lambda x: make_property(class_name, is_meta, x))
	
	print class_name
	print ivars
	
	protocollist_addr = Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'protocols'))
	if protocollist_addr:
		member_count = Dword(protocollist_addr)	
		for i in range(member_count):
			MakeStructEx(protocollist_addr + 4 + i * GetStrucSize(objc_protocol), -1, 'objc_protocol')

def apply_structures():
	objc_classlist = SegByName('__objc_classlist') # shouldn't there be a SegByBase around this? doesn't work though
	objc_classlist_end = SegEnd(objc_classlist)
	
	for i in range(objc_classlist, objc_classlist_end, 4):
		make_class(Dword(i))
		MakeDword(i)


	objc_selrefs = SegByName('__objc_selrefs')
	objc_selrefs_end = SegEnd(objc_selrefs)
	
	for i in range(objc_selrefs, objc_selrefs_end, 4):
		MakeDword(i)
		selector = GetString(Dword(i), -1, ASCSTR_C)
		MakeNameEx(i, "sel_" + selector, SN_NOCHECK)

make_structures()
apply_structures()