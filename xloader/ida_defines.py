# IDA Python SDK
from idaapi import *
from idc import *
from idautils import *

def IDAAPI_AskStr(defval, prompt):
    if IDA_SDK_VERSION >= 740:
        return ask_str(defval, 0, prompt)
    else:
        return AskStr(defval, prompt)

def IDAAPI_MakeRptCmt(ea, cmt):
    if IDA_SDK_VERSION >= 740:
        return set_cmt(ea, cmt, 1)
    else:
        return MakeRptCmt(ea, cmt)

def IDAAPI_MakeComm(ea, cmt):
    if IDA_SDK_VERSION >= 740:
        return set_cmt(ea, cmt, 0)
    else:
        return MakeComm(ea, cmt)

def IDAAPI_get_true_name(ea, param2):
    if IDA_SDK_VERSION >= 740:
        return get_name(ea, calc_gtn_flags(ea, ea))
    else:
        return get_true_name(ea, ea)

def IDAAPI_read_selection():
    if IDA_SDK_VERSION >= 740:
        return read_range_selection(None)
    else:
        return read_selection()

if IDA_SDK_VERSION >= 740:
    #defines
    IDAAPI_SETMENU_APP = SETMENU_APP
    IDAAPI_AST_ENABLE_ALWAYS = AST_ENABLE_ALWAYS
    IDAAPI_FUNCATTR_END = FUNCATTR_END
    IDAAPI_SN_CHECK = idc.SN_CHECK
    IDAAPI_SN_NOWARN = idc.SN_NOWARN
    IDAAPI_XREF_FAR = XREF_FAR
    #functions
    IDAAPI_ItemSize = get_item_size
    IDAAPI_Names = Names #idautils.Names
    IDAAPI_GetDisasm = GetDisasm
    IDAAPI_attach_action_to_menu = attach_action_to_menu
    IDAAPI_register_action = register_action
    IDAAPI_action_desc_t = action_desc_t
    IDAAPI_action_handler_t = action_handler_t
    IDAAPI_FindFuncEnd = find_func_end
    IDAAPI_FuncItems = FuncItems
    IDAAPI_XrefsTo = XrefsTo
    IDAAPI_GetMnem = print_insn_mnem
    IDAAPI_GetInputFilePath = get_input_file_path
    IDAAPI_GetIdbPath = get_idb_path
    IDAAPI_simplecustviewer_t = simplecustviewer_t
    IDAAPI_ItemHead = get_item_head
    IDAAPI_LocByName = get_name_ea_simple
    IDAAPI_Chunks = Chunks
    IDAAPI_Functions = Functions
    IDAAPI_GetFunctionName = get_func_name
    IDAAPI_GetOpType = get_operand_type
    IDAAPI_GetOperandValue = get_operand_value
    IDAAPI_Heads = Heads
    IDAAPI_GetManyBytes = get_bytes
    IDAAPI_Segments = Segments
    IDAAPI_get_func = get_func
    IDAAPI_FlowChart = FlowChart
    IDAAPI_GetFunctionAttr = get_func_attr
    IDAAPI_CommentEx = get_cmt
    IDAAPI_MakeFunction = add_func
    IDAAPI_get_func_name = get_func_name
    IDAAPI_get_name = get_name
    IDAAPI_ScreenEA     = get_screen_ea
    IDAAPI_IsCode       = is_code
    IDAAPI_DelItems     = del_items
    IDAAPI_MakeCode     = create_insn
    IDAAPI_GetFlags     = get_full_flags
    IDAAPI_SetColor     = set_color
    IDAAPI_IsLoaded     = is_loaded
    IDAAPI_HasValue     = has_value
    IDAAPI_GetBptQty    = get_bpt_qty
    IDAAPI_GetBptEA     = get_bpt_ea
    IDAAPI_GetBptAttr   = get_bpt_attr
    IDAAPI_SegStart     = get_segm_start
    IDAAPI_SegEnd       = get_segm_end
    IDAAPI_GetBytes     = get_bytes
    IDAAPI_AskYN        = ask_yn
    IDAAPI_AskFile      = ask_file
    IDAAPI_AskLong      = ask_long
    IDAAPI_NextHead     = next_head
    IDAAPI_PrevHead     = prev_head
    IDAAPI_GetDisasmEx  = generate_disasm_line
    IDAAPI_NextThat     = next_that
    IDAAPI_Jump         = jumpto
    IDAAPI_AddHotkey    = add_idc_hotkey
    IDAAPI_CompileLine  = compile_idc_text
    IDAAPI_MakeNameEx   = set_name
    IDAAPI_get_inf_structure = get_inf_structure
    IDAAPI_patch_byte   = patch_byte
    IDAAPI_patch_word   = patch_word
    IDAAPI_patch_dword  = patch_dword
    IDAAPI_get_original_byte = get_original_byte
    IDAAPI_XrefsFrom    = XrefsFrom
    IDAAPI_get_import_module_qty = get_import_module_qty
    IDAAPI_get_import_module_name = get_import_module_name
    IDAAPI_enum_import_names = enum_import_names
    IDAAPI_get_imagebase = get_imagebase
    IDAAPI_get_fileregion_ea = get_fileregion_ea
    IDAAPI_get_fileregion_offset = get_fileregion_offset
    IDAAPI_GetStringType = get_str_type
    IDAAPI_GetString = get_strlit_contents
    # classes
    IDAAPI_Choose = Choose
    IDAAPI_Form = Form
elif IDA_SDK_VERSION >= 700:
    #defines
    IDAAPI_SETMENU_APP = SETMENU_APP
    IDAAPI_AST_ENABLE_ALWAYS = AST_ENABLE_ALWAYS
    IDAAPI_FUNCATTR_END = FUNCATTR_END
    IDAAPI_SN_CHECK = idc.SN_CHECK
    IDAAPI_SN_NOWARN = idc.SN_NOWARN
    IDAAPI_XREF_FAR = XREF_FAR
    # functions
    IDAAPI_ItemSize = ItemSize
    IDAAPI_Names = Names #idautils.Names
    IDAAPI_GetDisasm = GetDisasm
    IDAAPI_attach_action_to_menu = attach_action_to_menu
    IDAAPI_register_action = register_action
    IDAAPI_action_desc_t = action_desc_t
    IDAAPI_action_handler_t = action_handler_t
    IDAAPI_FindFuncEnd = FindFuncEnd
    IDAAPI_FuncItems = FuncItems
    IDAAPI_XrefsTo = XrefsTo
    IDAAPI_GetMnem = GetMnem
    IDAAPI_GetInputFilePath = GetInputFilePath
    IDAAPI_GetIdbPath = GetIdbPath
    IDAAPI_simplecustviewer_t = simplecustviewer_t
    IDAAPI_ItemHead = ItemHead
    IDAAPI_LocByName = LocByName
    IDAAPI_Chunks = Chunks
    IDAAPI_Functions = Functions
    IDAAPI_GetFunctionName = GetFunctionName
    IDAAPI_GetOpType = GetOpType
    IDAAPI_GetOperandValue = GetOperandValue
    IDAAPI_Heads = Heads
    IDAAPI_GetManyBytes = GetManyBytes
    IDAAPI_Segments = Segments
    IDAAPI_get_func = get_func
    IDAAPI_FlowChart = FlowChart
    IDAAPI_GetFunctionAttr = GetFunctionAttr
    IDAAPI_CommentEx = CommentEx
    IDAAPI_MakeFunction = MakeFunction
    IDAAPI_get_func_name = get_func_name
    IDAAPI_get_name = get_name
    IDAAPI_ScreenEA     = get_screen_ea
    IDAAPI_IsCode       = is_code
    IDAAPI_DelItems     = del_items
    IDAAPI_MakeCode     = create_insn
    IDAAPI_GetFlags     = get_full_flags
    IDAAPI_SetColor     = set_color
    IDAAPI_IsLoaded     = is_loaded
    IDAAPI_HasValue     = has_value
    IDAAPI_GetBptQty    = get_bpt_qty
    IDAAPI_GetBptEA     = get_bpt_ea
    IDAAPI_GetBptAttr   = get_bpt_attr
    IDAAPI_SegStart     = get_segm_start
    IDAAPI_SegEnd       = get_segm_end
    IDAAPI_GetBytes     = get_bytes
    IDAAPI_AskYN        = ask_yn
    IDAAPI_AskFile      = ask_file
    IDAAPI_AskLong      = ask_long
    IDAAPI_NextHead     = next_head
    IDAAPI_PrevHead     = prev_head
    IDAAPI_GetDisasmEx  = generate_disasm_line
    IDAAPI_NextThat     = next_that
    IDAAPI_Jump         = jumpto
    IDAAPI_AddHotkey    = AddHotkey
    IDAAPI_CompileLine  = CompileLine
    IDAAPI_MakeNameEx   = MakeNameEx
    IDAAPI_get_inf_structure = get_inf_structure
    IDAAPI_patch_byte = patch_byte
    IDAAPI_patch_word = patch_word
    IDAAPI_patch_dword = patch_dword
    IDAAPI_get_original_byte = get_original_byte
    IDAAPI_XrefsFrom    = XrefsFrom
    IDAAPI_get_import_module_qty = get_import_module_qty
    IDAAPI_get_import_module_name = get_import_module_name
    IDAAPI_enum_import_names = enum_import_names
    IDAAPI_get_imagebase = get_imagebase
    IDAAPI_get_fileregion_ea = get_fileregion_ea
    IDAAPI_get_fileregion_offset = get_fileregion_offset
    IDAAPI_GetStringType = get_str_type
    IDAAPI_GetString = get_strlit_contents
    # classes
    IDAAPI_Choose = Choose
    IDAAPI_Form = Form
else:
    #defines
    IDAAPI_SETMENU_APP = SETMENU_APP
    IDAAPI_AST_ENABLE_ALWAYS = AST_ENABLE_ALWAYS
    IDAAPI_FUNCATTR_END = FUNCATTR_END
    IDAAPI_SN_CHECK = idc.SN_CHECK
    IDAAPI_SN_NOWARN = idc.SN_NOWARN
    IDAAPI_XREF_FAR = XREF_FAR
    # functions
    IDAAPI_ItemSize = ItemSize
    IDAAPI_Names = Names #idautils.Names
    IDAAPI_GetDisasm = GetDisasm
    IDAAPI_attach_action_to_menu = attach_action_to_menu
    IDAAPI_register_action = register_action
    IDAAPI_action_desc_t = action_desc_t
    IDAAPI_action_handler_t = action_handler_t
    IDAAPI_FindFuncEnd = FindFuncEnd
    IDAAPI_FuncItems = FuncItems
    IDAAPI_XrefsTo = XrefsTo
    IDAAPI_GetMnem = GetMnem
    IDAAPI_GetInputFilePath = GetInputFilePath
    IDAAPI_GetIdbPath = GetIdbPath
    IDAAPI_simplecustviewer_t = simplecustviewer_t
    IDAAPI_ItemHead = ItemHead
    IDAAPI_LocByName = LocByName
    IDAAPI_Chunks = Chunks
    IDAAPI_Functions = Functions
    IDAAPI_GetFunctionName = GetFunctionName
    IDAAPI_GetOpType = GetOpType
    IDAAPI_GetOperandValue = GetOperandValue
    IDAAPI_Heads = Heads
    IDAAPI_GetManyBytes = GetManyBytes
    IDAAPI_Segments = Segments
    IDAAPI_get_func = get_func
    IDAAPI_FlowChart = FlowChart
    IDAAPI_GetFunctionAttr = GetFunctionAttr
    IDAAPI_CommentEx = CommentEx
    IDAAPI_MakeFunction = MakeFunction
    IDAAPI_get_func_name = get_func_name
    IDAAPI_get_name = get_name
    IDAAPI_ScreenEA     = ScreenEA
    IDAAPI_IsCode       = isCode
    IDAAPI_DelItems     = MakeUnkn
    IDAAPI_MakeCode     = MakeCode
    IDAAPI_GetFlags     = getFlags
    IDAAPI_SetColor     = SetColor
    IDAAPI_IsLoaded     = isLoaded
    IDAAPI_HasValue     = hasValue
    IDAAPI_GetBptQty    = GetBptQty
    IDAAPI_GetBptEA     = GetBptEA
    IDAAPI_GetBptAttr   = GetBptAttr
    IDAAPI_SegStart     = SegStart
    IDAAPI_SegEnd       = SegEnd
    IDAAPI_GetBytes     = get_many_bytes
    IDAAPI_AskYN        = AskYN
    IDAAPI_AskFile      = AskFile
    IDAAPI_AskLong      = AskLong
    IDAAPI_NextHead     = NextHead
    IDAAPI_PrevHead     = PrevHead
    IDAAPI_GetDisasmEx  = GetDisasmEx
    IDAAPI_NextThat     = nextthat
    IDAAPI_Jump         = Jump
    IDAAPI_AddHotkey    = AddHotkey
    IDAAPI_CompileLine  = CompileLine
    IDAAPI_MakeNameEx   = MakeNameEx
    IDAAPI_get_inf_structure = get_inf_structure
    IDAAPI_patch_byte = PatchByte
    IDAAPI_patch_word = PatchWord
    IDAAPI_patch_dword = PatchDword
    IDAAPI_get_original_byte = GetOriginalByte
    IDAAPI_XrefsFrom    = XrefsFrom
    IDAAPI_get_import_module_qty = get_import_module_qty
    IDAAPI_get_import_module_name = get_import_module_name
    IDAAPI_enum_import_names = enum_import_names
    IDAAPI_get_imagebase = get_imagebase
    IDAAPI_get_fileregion_ea = get_fileregion_ea
    IDAAPI_get_fileregion_offset = get_fileregion_offset
    IDAAPI_GetStringType = GetStringType
    IDAAPI_GetString = GetString
    # classes
    IDAAPI_Choose = Choose2
    IDAAPI_Form = Form