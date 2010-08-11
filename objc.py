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

def process_list(start_addr, type, processor = None):
	if start_addr != 0:
		MakeStructEx(start_addr, -1, 'objc_listheader')
		
		member_size  = Dword(start_addr + GetMemberOffset(objc_listheader, 'member_size'))
		member_count = Dword(start_addr + GetMemberOffset(objc_listheader, 'member_count'))
		
		for i in range(member_count):
			MakeStructEx(start_addr + 8 + i * member_size, -1, type)
			if processor:
				processor(start_addr + 8 + i * member_size)


def apply_structures():
	objc_classlist = SegByName('__objc_classlist') # shouldn't there be a SegByBase around this? doesn't work though
	objc_classlist_end = SegEnd(objc_classlist)
	
	for i in range(objc_classlist, objc_classlist_end, 4):
		class_addr = Dword(i)
		MakeStructEx(class_addr, -1, 'objc_class')
		MakeStructEx(Dword(class_addr + GetMemberOffset(objc_class, 'metaclass')), -1, 'objc_class')
				
		classinfo_addr = Dword(class_addr + GetMemberOffset(objc_class, 'classinfo'))
		MakeStructEx(classinfo_addr, -1, 'objc_classinfo')
		
		class_name_addr = Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'name'))
		class_name = GetString(class_name_addr, -1, ASCSTR_C)
		
		def apply_method_name(method_addr):	
			name_addr = Dword(method_addr + GetMemberOffset(objc_method, "name"))
			code_addr = Dword(method_addr + GetMemberOffset(objc_method, "code")) & 0xFFFFFFFE # ignore thumb indicator

			MakeNameEx(code_addr, class_name + "__" + GetString(name_addr, -1, ASCSTR_C), SN_NOCHECK)
		
		process_list(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'methods'   )), 'objc_method', apply_method_name)
		process_list(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'ivars'     )), 'objc_ivar'  )
		process_list(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'properties')), 'objc_ivar'  )
		
		protocollist_addr = Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'protocols'))
		if protocollist_addr != 0:
			member_count = Dword(protocollist_addr)	
			for i in range(member_count):
				MakeStructEx(protocollist_addr + 4 + i * GetStrucSize(objc_protocol), -1, 'objc_protocol')
		
		
		MakeDword(i)


make_structures()
apply_structures()