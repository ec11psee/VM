from neodict2xml import dict2xml
import xml.etree.ElementTree as et
import json
def tests_ref(data,operators_list):
    if type(data)==dict:
        for key in data.keys():
            tip=type(data[key])
            if tip not in  [dict,tuple,list]:
                if key=='test_ref':
                    operators_list.append(data[key])
            else:
                tests_ref(data[key],operators_list)
    elif type(data)==tuple or type(data)==list:
        for elemnt in data:
            tests_ref(elemnt,operators_list)
    return(operators_list)

def criteria_obrabotka(crit,lvl):
    if type(crit)==tuple:
        if 'operator' in crit[0].keys():
            print('-'*lvl,crit[0]['operator'])
            for i in range(1,len(crit)):
                criteria_obrabotka(crit[i],lvl)
        else:

            print('-'*lvl,crit[0]['comment'])
    if type(crit)==dict:
        if '{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion' in crit.keys():
            if type(crit['{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion'][0])!=tuple:
                print('-'*lvl,crit['{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion'][0]['comment'])
            else:
                for elem in crit['{http://oval.mitre.org/XMLSchema/oval-definitions-5}criterion']:
                    print('-'*lvl,elem[0]['comment'])
        if '{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria' in crit.keys():
            criteria_obrabotka(crit['{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria'],lvl+1)
    if type(crit)==list:
        for el in crit:
            criteria_obrabotka(el,lvl+1)
file='rhel-8.oval.xml'

with open(file,'r',encoding='utf-8') as text:
     file=text.read()
     dannie=dict2xml.from_xml(file)
     spisok_tests=dannie['{http://oval.mitre.org/XMLSchema/oval-definitions-5}oval_definitions'][1]['{http://oval.mitre.org/XMLSchema/oval-definitions-5}tests']
     dict_tests={}
     for group_tests in spisok_tests.keys():
         for test in spisok_tests[group_tests]:
            dict_tests[test[0]['id']]={}
            dict_tests[test[0]['id']]['check']=test[0]['check']
            dict_tests[test[0]['id']]['comment']=test[0]['comment']
            for key_refs in test[1].keys():
                if 'object_ref' in test[1][key_refs][0].keys():
                    dict_tests[test[0]['id']]['object_ref']=test[1][key_refs][0]['object_ref']
                elif 'state_ref' in  test[1][key_refs][0].keys():
                    dict_tests[test[0]['id']]['state_ref']=test[1][key_refs][0]['state_ref']
     spisok_obj=dannie['{http://oval.mitre.org/XMLSchema/oval-definitions-5}oval_definitions'][1]['{http://oval.mitre.org/XMLSchema/oval-definitions-5}objects']
     dict_obj={}
     for group_obj in spisok_obj.keys():
         if type(spisok_obj[group_obj])==list:
             for obj in spisok_obj[group_obj]:
                 if type(obj)==tuple:
                     dict_obj[obj[0]['id']]=obj[1]
         else:
             if len(spisok_obj[group_obj])>1:
                dict_obj[spisok_obj[group_obj][0]['id']]=spisok_obj[group_obj][1]
             else:
                 dict_obj[spisok_obj[group_obj][0]['id']]='Отсутсвуют параметры'
     spisok_states=dannie['{http://oval.mitre.org/XMLSchema/oval-definitions-5}oval_definitions'][1]['{http://oval.mitre.org/XMLSchema/oval-definitions-5}states']
     dict_states={}
     for group_state in spisok_states.keys():
         for state in spisok_states[group_state]:
             if type(state)==tuple:
                 dict_states[state[0]['id']]=state[1]
     spisok_uyaz=dannie['{http://oval.mitre.org/XMLSchema/oval-definitions-5}oval_definitions'][1]['{http://oval.mitre.org/XMLSchema/oval-definitions-5}definitions']['{http://oval.mitre.org/XMLSchema/oval-definitions-5}definition']
     states={}
     objects={}
     tests={}
     results={}
     for index_uyaz in range(3):
         fields_uyaz=spisok_uyaz[index_uyaz]
         vuln_id=fields_uyaz[0]['id']
         vuln_metadata=fields_uyaz[1]['{http://oval.mitre.org/XMLSchema/oval-definitions-5}metadata']
         vuln_title=vuln_metadata['{http://oval.mitre.org/XMLSchema/oval-definitions-5}title']
         vuln_description=vuln_metadata['{http://oval.mitre.org/XMLSchema/oval-definitions-5}description']
         vuln_aff=vuln_metadata['{http://oval.mitre.org/XMLSchema/oval-definitions-5}affected']
         vuln_family=vuln_aff[0]['family']
         vuln_platform=vuln_aff[1]['{http://oval.mitre.org/XMLSchema/oval-definitions-5}platform']
         vuln_advisor=vuln_metadata['{http://oval.mitre.org/XMLSchema/oval-definitions-5}advisory']
         if '{http://oval.mitre.org/XMLSchema/oval-definitions-5}cve' in vuln_advisor[1].keys():
             vulv_cve=vuln_advisor[1]['{http://oval.mitre.org/XMLSchema/oval-definitions-5}cve']
             if type(vulv_cve[0])==dict:
                 vuln_cve_crit=vulv_cve[0]['cvss3'].split('/')[0]
                 vuln_cve_naprav=vulv_cve[0]['cvss3'].lstrip(vuln_cve_crit+'/CVSS:3.0/')
                 vuln_cve_id=vulv_cve[-1]
             else:
                 vuln_cve_naprav=[]
                 vuln_cve_crit=[]
                 vuln_cve_id=[]
                 for vuln_cve_el in vulv_cve:
                     vuln_cve_crit.append(vuln_cve_el[0]['cvss3'].split('/')[0])
                     vuln_cve_naprav.append(vuln_cve_el[0]['cvss3'].lstrip(vuln_cve_el[0]['cvss3'].split('/')[0]+'/CVSS:3.0/'))
                     vuln_cve_id.append(vuln_cve_el[-1])
         vuln_creterias=fields_uyaz[1]['{http://oval.mitre.org/XMLSchema/oval-definitions-5}criteria']
         operators_list=[]
         tests_list=tests_ref(vuln_creterias,operators_list)
         for test in tests_list:
             tests[test]=dict_tests[test]
         for test in tests.keys():
             states[tests[test]['state_ref']]=dict_states[tests[test]['state_ref']]
             objects[tests[test]['object_ref']]=dict_obj[tests[test]['object_ref']]
         results[vuln_id]={
         'vulner_tittle':vuln_title,
         'vulner_description':vuln_description,
         'vulner_family':vuln_family,
         'vulner_platform':vuln_platform,
         'vulner_direction':vuln_cve_naprav,
         'vulner_CVE_id':vuln_cve_id,
         'vulner_score':vuln_cve_crit,
         'vulner_criteria':vuln_creterias}

     final={'definitions':results,'tests':tests,'states':states,'objects':objects}

# Ну и структура данных
#Получение списка уязвимостей
print(final['definitions'].keys())
#Отображение критериев для конкретной уязвимости
criteria_obrabotka(final['definitions']['oval:com.redhat.rhba:def:20193384']['vulner_criteria'],0)
#Получение информации об уязвимости
print(final['definitions']['oval:com.redhat.rhba:def:20193384'])
with open('result.json', 'w') as file_json:
    json.dump(final,file_json)
