from idaapi import *
from idautils import *
from idc import *

register = re.compile('(..)')
simple_mem = re.compile('\[(..)\]')
simple_memoff = re.compile('\[(..),(..)\]')

def make_structures():
	global objc_class, objc_classinfo, objc_listheader, objc_method, objc_protocol, objc_ivar, objc_category, objc_property
	
	objc_class = GetStrucIdByName('objc_class')
	objc_classinfo = GetStrucIdByName('objc_classinfo')
	objc_listheader = GetStrucIdByName('objc_listheader')
	objc_method = GetStrucIdByName('objc_method')
	objc_protocol = GetStrucIdByName('objc_protocol')
	objc_ivar = GetStrucIdByName('objc_ivar')
	objc_category = GetStrucIdByName('objc_category')
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
		AddStrucMember(objc_protocol, 'protocols', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_protocol, 'methods0', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_protocol, 'methods1', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_protocol, 'methods2', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
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

	if objc_category == 4294967295:		
		objc_category = AddStruc(-1, 'objc_category')
		AddStrucMember(objc_category, 'name', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_category, 'target', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_category, 'methods0', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_category, 'methods1', -1, idaapi.FF_DWRD | idaapi.FF_0OFF | idaapi.FF_DATA, -1, 4, -1, 0, REF_OFF32)
		AddStrucMember(objc_category, 'unk2', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)	
		AddStrucMember(objc_category, 'unk3', -1, idaapi.FF_DWRD | idaapi.FF_DATA, -1, 4)	
		
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
	code_addr = Dword(addr + GetMemberOffset(objc_method, "code")) & 0xFFFFFFFE # ignore thumb indicator
	
	method_name = GetString(Dword(addr + GetMemberOffset(objc_method, "name")), -1, ASCSTR_C)
	method_type = GetString(Dword(addr + GetMemberOffset(objc_method, "type")), -1, ASCSTR_C)
	
	if is_meta:
		MakeRptCmt(code_addr, "+[%s %s]" % (class_name, method_name))
		MakeNameEx(code_addr, "%s_meta_%s" % (class_name, method_name), SN_NOCHECK)
	else:
		MakeRptCmt(code_addr, "-[%s %s]" % (class_name, method_name))
		MakeNameEx(code_addr, "%s_%s" % (class_name, method_name), SN_NOCHECK)

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
	# TODO: parse the type info, etc.
	MakeStructEx(addr, -1, 'objc_property')

def make_protolist(addr):
	if addr == 0:
		return
	
	MakeDword(addr)
	member_count = Dword(addr)	
	for i in range(member_count):
		make_protocol(Dword(addr + 4 + i * 4))
		MakeDword(addr + 4 + i * 4)


def make_protocol(addr):
	if addr == 0:
		return
		
	MakeStructEx(addr, -1, 'objc_protocol')
		
	protocol_name = GetString(Dword(addr + GetMemberOffset(objc_protocol, 'name')), -1, ASCSTR_C)
	MakeNameEx(addr, 'proto_' + protocol_name, SN_NOCHECK)
	
	process_list(Dword(addr + GetMemberOffset(objc_protocol, 'methods0')), lambda x: make_method(protocol_name, False, x))
	process_list(Dword(addr + GetMemberOffset(objc_protocol, 'methods1')), lambda x: make_method(protocol_name, False, x))
	process_list(Dword(addr + GetMemberOffset(objc_protocol, 'methods2')), lambda x: make_method(protocol_name, False, x))

	make_protolist(Dword(addr + GetMemberOffset(objc_protocol, 'protocols')))
	

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
	
	#if class_name:
	#	if is_meta:
	#		MakeNameEx(addr, 'meta_' + class_name, SN_NOCHECK)
	#	else:
	#		MakeNameEx(addr, 'class_' + class_name, SN_NOCHECK)
	
	process_list(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'methods'   )), lambda x: make_method(class_name, is_meta, x)) # man, I want partial application...
	ivars = process_list(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'ivars'     )), lambda x: make_ivar(class_name, is_meta, x))
	process_list(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'properties')), lambda x: make_property(class_name, is_meta, x))
		
	make_protolist(Dword(classinfo_addr + GetMemberOffset(objc_classinfo, 'protocols')))
	

def make_category(addr):
	if addr == 0:
		return
	
	MakeStructEx(addr, -1, 'objc_category')
	category_name = GetString(Dword(addr + GetMemberOffset(objc_category, 'name')), -1, ASCSTR_C)
	
	target_addr = Dword(addr + GetMemberOffset(objc_category, 'target'))
	target_name = ''
	if target_addr:
		target_classinfo_addr = Dword(target_addr + GetMemberOffset(objc_class, 'classinfo'))
		target_name = GetString(Dword(target_classinfo_addr + GetMemberOffset(objc_classinfo, 'name')), -1, ASCSTR_C)
		
	process_list(Dword(addr + GetMemberOffset(objc_category, 'methods0')), lambda x: make_method('%s(%s)' % (target_name, category_name), False, x))
	process_list(Dword(addr + GetMemberOffset(objc_category, 'methods1')), lambda x: make_method('%s(%s)' % (target_name, category_name), False, x))

'''
def trace_ivar(addr, ivar_name):
	
	for xref in XrefsTo(addr):
		if isCode(xref.frm) and GetMnem(xref.frm) == 'LDR':
			func_end = GetFunctionAttr(xref.frm, FUNCATTR_END)
			
			# Where did our xref end up?
			regs = {GetOpnd(xref.frm, 0): True}
			
			pos = NextHead(xref.frm, func_end)
			while pos < func_end:								
				if GetMnem(pos) in ['LDR', 'MOV']:
					dest_reg = GetOpnd(pos, 0)
					info = simple_mem.match(GetOpnd(pos, 1))
					if info:
						regs[dest_reg] = [regs.get(info.group(1))]
					elif register.match(GetOpnd(pos, 1)):
						regs[dest_reg] = regs.get(GetOpnd(pos, 1))
					else:
						regs[dest_reg] = None # We're lost (TODO: make this more sophisticated)
					
				print regs					
				
				pos = NextHead(pos, func_end)
			
			break
'''

def apply_structures():
	objc_classlist = SegByName('__objc_classlist') # shouldn't there be a SegByBase around this? doesn't work though
	objc_classlist_end = SegEnd(objc_classlist)
	
	for i in range(objc_classlist, objc_classlist_end, 4):
		make_class(Dword(i))
		MakeDword(i)
		
	objc_classrefs = SegByName('__objc_classrefs')
	objc_classrefs_end = SegEnd(objc_classrefs)
	
	for i in range(objc_classrefs, objc_classrefs_end, 4):
		make_class(Dword(i))			
		MakeDword(i)

	objc_selrefs = SegByName('__objc_selrefs')
	objc_selrefs_end = SegEnd(objc_selrefs)
	
	for i in range(objc_selrefs, objc_selrefs_end, 4):
		selector = GetString(Dword(i), -1, ASCSTR_C)
		MakeNameEx(i, "sel_" + selector, SN_NOCHECK)
		MakeDword(i)

	objc_catlist = SegByName('__objc_catlist')
	objc_catlist_end = SegEnd(objc_catlist)

	for i in range(objc_catlist, objc_catlist_end, 4):
		make_category(Dword(i))
		MakeDword(i)
	
	# TODO: Factor this pattern out
	objc_protolist = SegByName('__objc_protolist')
	objc_protolist_end = SegEnd(objc_protolist)

	for i in range(objc_protolist, objc_protolist_end, 4):
		make_protocol(Dword(i))
		MakeDword(i)
		
	objc_superrefs = SegByName('__objc_superrefs')
	objc_superrefs_end = SegEnd(objc_superrefs)

	for i in range(objc_superrefs, objc_superrefs_end, 4):
		MakeDword(i)
	

make_structures()
apply_structures()
#trace_ivar(0xD77A0, '_context')