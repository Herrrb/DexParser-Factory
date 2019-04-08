from dexparser import Dexparser
import struct


dex = Dexparser('../../classes.dex')

string_list = dex.string_list()


# ----------------------
# 打印类名
type_list = dex.typeid_list()
type_len = len(type_list)
print('type list --> count:', str(type_len))

type_string_list = []
for index in type_list:
    """
    struct DexTypeId {
        u4 descriptionIdx;
    }
    """
    type_string_list.append(str(string_list[index]))

print('\n'.join(type_string_list))

# ----------------------
# 打印原型列表

print('-*-' * 30)

proto_list = dex.protoids_list()
proto_len = len(proto_list)

proto_string_list = []
for proto in proto_list:
    """
    struct DexProtoId {
        u4 shortIdx;
        u4 returnTypeIdx;
        u4 parametersOff;
    }
    """
    name_index = proto[0]
    return_index = proto[1]
    param_index = proto[2]

    """
    struct DexTypeList {
        u4 size;
        DexTypeItem list[1];
    }
    struct DexTypeItem {
        u2 typeIdx;
    }
    """
    desc = {}
    desc['name'] = string_list[name_index]
    desc['return'] = type_string_list[return_index]
    desc['param'] = []

    if param_index != 0:
        param_size = struct.unpack('<L', dex.mmap[param_index: param_index+4])[0]

        if param_size > 0:
            for i in range(param_size):
                # 在这里体现出
                # u2 typeIdx;
                item = struct.unpack('<H', dex.mmap[param_index + i*2 + 4: param_index + i*2 + 6])[0]
                desc['param'].append(type_string_list[item])
    
    proto_string_list.append("%s %s(%s)" % (desc['return'], '%s', ''.join(desc['param'])))

print('\n'.join(proto_string_list))


# 分割
print('-*-' * 30)
# 打印方法列表
method_list = dex.method_list()
method_len = len(method_list)
print("method list --> count:", method_len)

method_string_list = []
for method in method_list:
    """
    struct DexMethodId {
        u2 classIdx;        类的类型 -> type_idx
        u2 protoIdx;        声明类型 -> proto_idx
        u4 nameIdx;         方法名   -> string_idx
    }
    """
    classid = method[0]
    protoid = method[1]
    nameid = method[2]

    desc = '%s --> %s' % (type_string_list[classid], proto_string_list[protoid] % string_list[nameid])
    method_string_list.append(desc)

print('\n'.join(method_string_list))


# 分割线
print('-*-' * 30)

field_list = dex.fieldids_list()
field_len = len(field_list)
print("field list --> count:", str(field_len))

field_string_list = []
for field in field_list:
    """
    struct DexFileId {
        u2 classIdx;       类的类型 -> type_idx
        u2 typeIdx;        字段类型 -> type_idx
        u4 nameIdx;        字段名称 -> string_idx
    }
    """
    classid = field[0]
    typeid = field[1]
    nameid = field[2]

    desc = '%s --> %s %s' % (type_string_list[classid], type_string_list[typeid], string_list[nameid])
    field_string_list.append(desc)

print('\n'.join(field_string_list))


# 最后将打印出来的五大索引区域的列表信息，都保存到文件中
# save_file = open('save.log', 'w')
# title = '%s\n---> %s <---\n%s\n' % ('-*-'*30, '%s', '-*-'*30)
# save_file.write("%s%s\n%s%s\n%s%s\n%s%s\n%s%s\n" % (\
#     title % 'string', '\n'.join(string_list),\
#     title % 'type', '\n'.join(type_string_list), \
#     title % 'proto', '\n'.join(proto_string_list), \
#     title % 'method', '\n'.join(method_string_list), \
#     title % 'field', '\n'.join(field_string_list) \
#     ))
# save_file.close()

print("-*-" * 40)

class_list = dex.classdef_list()
for classitem in class_list:
    class_id = classitem[0]
    access_flag = classitem[1]
    superclass_idx = classitem[2]
    interfaces_off = classitem[3]
    source_file_idx = classitem[4]
    annotation_off = classitem[5]
    class_data_off = classitem[6]
    static_values_off = classitem[7]

    implement_content = ''
    # interfaces = 

    print("%x: %s ---> %s %s extends %s %s" % (class_id, string_list[source_file_idx], access_flag, type_string_list[class_id], type_string_list[superclass_idx], implement_content))

print("-*-" * 40)

