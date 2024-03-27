from neodict2xml import dict2xml
import xml.etree.ElementTree as et



def print_root(lvl,data):
    if type(data)==dict:
        for key in data.keys():
            print('-'*lvl,lvl,"|ключ: ",key)
            print_root(lvl+1,data[key])
    elif type(data)==tuple or type(data)==list:
        print_root(lvl+1,data[0])
        if len(data)>1:
            print_root(lvl+1,data[1])
    else:
        print(f"{'-'*lvl}{lvl}| {data}")



file='rhel-8.oval.xml'

with open(file,'r',encoding='utf-8') as text:
     file=text.read()
     dannie=dict2xml.from_xml(file)
     print_root(0,dannie)
