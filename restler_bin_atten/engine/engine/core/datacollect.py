import os
import pickle
import random
import datetime
from threading import Thread
import subprocess
import time

import engine.core.sequences as sequences
seq_collection_origin = [sequences.Sequence()]

tmptmpcount = 0 
countid = 0
countid400 = 0

requestid = {}

trainingset = []
trainingset400 = []
mutationtrainingset = {}
mutationlist = {}
whether_start_mutation_list = 0
generation_key = 0
seq_gen200 = 0
seq_gen400 = 0
seq_gen500 = 0
seq_nogen200 = 0
seq_nogen400 = 0
seq_nogen500 = 0
seq_if = 0
seq_which = 0
seq_gen_num = 0
seq_nogen_num = 0


gen200 = 0
gen400 = 0
gen500 = 0
nogen200 = 0
nogen400 = 0
nogen500 = 0


payload_body_checker_former_200 = 0
payload_body_checker_former_500 = 0
payload_body_checker_former_400 = 0
payload_body_checker_laster_200 = 0
payload_body_checker_laster_500 = 0
payload_body_checker_laster_400 = 0


invalid_dynamic_object_checker_former_200 = 0
invalid_dynamic_object_checker_former_500 = 0
invalid_dynamic_object_checker_former_400 = 0

leakage_rule_checker_former_200 = 0
leakage_rule_checker_former_500 = 0
leakage_rule_checker_former_400 = 0



namespace_rule_checker_former_200 = 0
namespace_rule_checker_former_500 = 0
namespace_rule_checker_former_400 = 0
namespace_rule_checker_laster_200 = 0
namespace_rule_checker_laster_500 = 0
namespace_rule_checker_laster_400 = 0



resource_hierarchy_checker_former_200 = 0
resource_hierarchy_checker_former_500 = 0
resource_hierarchy_checker_former_400 = 0
resource_hierarchy_checker_laster_200 = 0
resource_hierarchy_checker_laster_500 = 0
resource_hierarchy_checker_laster_400 = 0



use_after_free_checker_laster_200 = 0
use_after_free_checker_laster_500 = 0
use_after_free_checker_laster_400 = 0

data_driven_checker_laster_200 = 0
data_driven_checker_laster_500 = 0
data_driven_checker_laster_400 = 0
data_driven_checker_former_200 = 0
data_driven_checker_former_500 = 0
data_driven_checker_former_400 = 0

starttime = 0
ppid = 0

seq_overall_200 = 0
seq_overall_400 = 0
seq_overall_500 = 0
seq_overall_non200 = 0

seq_part_200 = 0
seq_part_400 = 0
seq_part_500 = 0
seq_part_non200 = 0

invalid_dynamic_object_checker_overall_200 = 0
invalid_dynamic_object_checker_overall_400 = 0
invalid_dynamic_object_checker_overall_500 = 0
invalid_dynamic_object_checker_overall_non200 = 0
invalid_dynamic_object_checker_part_200 = 0
invalid_dynamic_object_checker_part_400 = 0
invalid_dynamic_object_checker_part_500 = 0
invalid_dynamic_object_checker_part_non200 = 0

namespace_rule_checker_overall_200 = 0
namespace_rule_checker_overall_400 = 0
namespace_rule_checker_overall_500 = 0
namespace_rule_checker_overall_non200 = 0
namespace_rule_checker_part_200 = 0
namespace_rule_checker_part_400 = 0
namespace_rule_checker_part_500 = 0
namespace_rule_checker_part_non200 = 0

payload_body_checker_overall_200 = 0
payload_body_checker_overall_400 = 0
payload_body_checker_overall_500 = 0
payload_body_checker_overall_non200 = 0
payload_body_checker_part_200 = 0
payload_body_checker_part_400 = 0
payload_body_checker_part_500 = 0
payload_body_checker_part_non200 = 0

resource_hierarchy_checker_overall_200 = 0
resource_hierarchy_checker_overall_400 = 0
resource_hierarchy_checker_overall_500 = 0
resource_hierarchy_checker_overall_non200 = 0
resource_hierarchy_checker_part_200 = 0
resource_hierarchy_checker_part_400 = 0
resource_hierarchy_checker_part_500 = 0
resource_hierarchy_checker_part_non200 = 0


seq_normal_writer = 0
seq_abnormal_writer = 0
seq_abnormal_consumer = 0

seq_types = []
valid_seq_types = []

writer_stats = {}

def readdata():
    global mutationlist
    global mutationtrainingset
    global requestid
    tmpmutationlist = {}
    if os.path.exists('/home/MINER/restler_bin_atten/mutationlist.pkl'):
        tmpmutationlist = pickle.load(open("/home/MINER/restler_bin_atten/mutationlist.pkl", 'rb'))
    for key1 in  tmpmutationlist.keys():
        if key1 not in mutationlist.keys():
            tmpvalue1 = []
            for value1 in tmpmutationlist[key1]:
                tmpvalue1.append(value1)
            mutationlist[key1] = tmpvalue1
        else:
            for value1 in tmpmutationlist[key1]:
                mutationlist[key1].append(value1)

    if os.path.exists('/home/MINER/restler_bin_atten/dictrequestid.pkl'):
        with open('/home/MINER/restler_bin_atten/dictrequestid.pkl', 'rb') as f:
            requestid = pickle.load(f)


    if os.path.exists('/home/MINER/restler_bin_atten/trainingset.pkl'):
        tmptrainingset = pickle.load(open("/home/MINER/restler_bin_atten/trainingset.pkl", 'rb'))
    
        for case in tmptrainingset:
            if case[2] == 'name=':
                tmptrainingset.remove(case)
        for lyui in range(len(tmptrainingset)):
            # buildup  dictcount
            tmptrainingset[lyui][1] = str(tmptrainingset[lyui][1]) + tmptrainingset[lyui][4]

            tmpword = ''
            for lyuk in range(len(tmptrainingset[lyui][3])):
                tmpword += tmptrainingset[lyui][3][lyuk]
            tup = (tmptrainingset[lyui][2], tmpword)
            if tmptrainingset[lyui][1] not in mutationtrainingset:
                dict1d = {}

                dict1d[tup] = 1
                mutationtrainingset[tmptrainingset[lyui][1]] = dict1d
            elif tup not in mutationtrainingset[tmptrainingset[lyui][1]]:
                dict1d = mutationtrainingset[tmptrainingset[lyui][1]]
                dict1d[tup] = 1
            else:
                mutationtrainingset[tmptrainingset[lyui][1]][tup] += 1

def reverseindex(tmplist, tmpword):
    start_loc = 0
    for lyui in range(0, len(tmplist)):
        if tmplist[len(tmplist) - 1 - lyui] == tmpword:
            start_loc = len(tmplist) - 1 - lyui
            break
    return start_loc

def retrainingmodel():
    t = Thread(target=retrain)
    t.start()

def retrain():
    global mutationlist
    global requestid
    global trainingset
    global whether_start_mutation_list
    global seq_gen200
    global seq_gen400
    global seq_gen500
    global seq_nogen200
    global seq_nogen400
    global seq_nogen500
    global seq_gen_num
    global seq_nogen_num
    whether_start_mutation_list += 1

    score_gen = (seq_gen200*3 + seq_gen500 - seq_gen400*2)*seq_nogen_num
    score_nogen = (seq_nogen200*3 + seq_nogen500 - seq_nogen400*2)*seq_gen_num

    print("start retrainingmodel")
    retrainingmodel_path = os.path.join(os.getcwd(),'retrainingmodel.txt')
    mutationlist_sum = 0
    for key in mutationlist:
        for l1 in mutationlist[key]:
            mutationlist_sum += len(l1)
    with open(retrainingmodel_path, 'a') as f:
        f.write("start retrainingmodel\n" + str(whether_start_mutation_list) +"\n")
        f.write("mutation_list length: "+str(len(mutationlist))+"\nmutationlist_sum: "+str(mutationlist_sum)+"\nnowtime: "+str(datetime.datetime.now())+"\n")
    with open('/home/MINER/restler_bin_atten/dictrequestid.pkl', 'wb') as f:
        pickle.dump(requestid, f, pickle.HIGHEST_PROTOCOL)

    with open('/home/MINER/restler_bin_atten/trainingset.pkl', 'wb') as f:
        pickle.dump(trainingset, f, pickle.HIGHEST_PROTOCOL)

    trainingset = []
    cmd = 'python /home/MINER/attentionmodel_group/attention.py'
    os.system(cmd)
    cmd = 'python /home/MINER/attentionmodel_group/generation.py'
    os.system(cmd)
    readdata()

    mutationlist_sum = 0
    for key in mutationlist:
        for l1 in mutationlist[key]:
            mutationlist_sum += len(l1)
    with open(retrainingmodel_path, 'a') as f:
        if whether_start_mutation_list > 1:
            score_gen1 = (seq_gen200*3 + seq_gen500 - seq_gen400*2)*(seq_nogen200+seq_nogen500+seq_nogen400)*1.2
            score_nogen1 = (seq_nogen200*3 + seq_nogen500 - seq_nogen400*2)*(seq_gen200+seq_gen500+seq_gen400)
            f.write("seq_gen200: " + str(seq_gen200) + "   seq_gen500: "+ str(seq_gen500) +"   seq_gen400: "+ str(seq_gen400) +"   seq_gen_num: "+ str(seq_gen200+seq_gen500+seq_gen400) +"\n")
            f.write("seq_nogen200: " + str(seq_nogen200) + "   seq_nogen500: "+ str(seq_nogen500) +"   seq_nogen400: "+ str(seq_nogen400) +"   seq_nogen_num: "+ str(seq_nogen200+seq_nogen500+seq_nogen400) +"\n")
            f.write("score_gen: " + str(score_gen1) + "   score_nogen: "+ str(score_nogen1) +"\n")
        f.write("finish readdata\nmutation_list length: "+str(len(mutationlist))+"\nmutationlist_sum: "+str(mutationlist_sum)+"\nnowtime: "+str(datetime.datetime.now())+"\n\n")
    print("finish readdata")


def get_writer_stat(req_collection, fuzzing_monitor, global_lock):
    from engine.transport_layer.response import VALID_CODES
    from engine.transport_layer.response import RESTLER_INVALID_CODE

    num_writer = 0
    num_valid_writer = 0
    for r in req_collection:
        query_result = fuzzing_monitor.query_status_codes_monitor(r, VALID_CODES, [RESTLER_INVALID_CODE], global_lock)
        if bool(r.metadata) and 'post_send' in r.metadata\
        and 'parser' in r.metadata['post_send']:
            num_writer += 1
            if query_result.fully_valid:
                num_valid_writer += 1
    
    return num_valid_writer, num_writer

