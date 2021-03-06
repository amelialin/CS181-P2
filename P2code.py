# -*- coding: utf-8 -*-
"""
Created on Thu Mar 03 15:51:11 2016

@author: WouterD
"""

# Example Feature Extraction from XML Files
# We count the number of specific system calls made by the programs, and use
# these as our features.
 
# This code requires that the unzipped training set is in a folder called "train". 
 
"""
@author: amelialin
 
Running this script creates a feature matrix X_train by parsing files in the 'train' directory, and also outputs X_train and t_train to csv. When run from the command line, this script takes 2 arguments: 1) The model # to use, and 2) the number of training files to use (out of a max of 3086).
"""


 
import os
from collections import Counter
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
import numpy as np
from scipy import sparse
import pandas as pd
from sknn.mlp import Regressor, Layer, Classifier
import sys
import logging
from sklearn.cross_validation import train_test_split


# os.chdir("C:\Users\WouterD\Dropbox\Recent Work Wouter\Harvard\kaggle")
import util

# os.chdir("C:\Users\WouterD\Dropbox\Recent Work Wouter\Harvard\kaggle\malware_train.tar\malware_train")

TRAIN_DIR = "train"
#TRAIN_DIR = "C:\Users\WouterD\Dropbox\Recent Work Wouter\Harvard\kaggle\malware_train.tar\malware_train"
 
call_set = set([])
 
# these are the fifteen malware classes we're looking for
malware_classes = ["Agent", "AutoRun", "FraudLoad", "FraudPack", "Hupigon", "Krap",
           "Lipler", "Magania", "None", "Poison", "Swizzor", "Tdss",
           "VB", "Virut", "Zbot"]
 
def add_to_set(tree):
    for el in tree.iter():
        call = el.tag
        call_set.add(call)
 
def create_data_matrix(start_index, end_index, direc="train"):
    X_calls = None
    X_custom_text = None
    classes = []
    ids = [] 
    i = -1
    for datafile in os.listdir(direc):
        # print(datafile,"datafile")        
        if datafile == '.DS_Store':
            continue
 
        i += 1
        if i < start_index:
            continue
        if i >= end_index:
            break
 
        print "datafile", i+1, datafile
 
        # extract id and true class (if available) from filename
        id_str, clazz = datafile.split('.')[:2]
        ids.append(id_str)
 
        # add target class if this is training data
        try:
            classes.append(util.malware_classes.index(clazz))
 
        except ValueError:
            # we should only fail to find the label in our list of malware classes
            # if this is test data, which always has an "X" label
            assert clazz == "X"
            classes.append(-1)
 
        # parse file as an xml document
        tree = ET.parse(os.path.join(direc,datafile))
        add_to_set(tree)
 
        this_row = call_feats(tree)
        if X_calls is None: # if X is empty
            X_calls = this_row 
        else:
            X_calls = np.vstack((X_calls, this_row))
 
        # parse files as lowercase text files
        with open("train/"+ datafile, "r") as myfile:
            text = myfile.read().lower()
        this_row = custom_text_features(text)
        if X_custom_text is None: # if X is empty
            X_custom_text = this_row 
        else:
            X_custom_text = np.vstack((X_custom_text, this_row))
 
    # turn arrays of dicts into Pandas DFs
    X_calls = make_matrix(X_calls)
    X_custom_text = make_matrix(X_custom_text)
 
    # concatenate into one feature matrix
    frames = [X_calls, X_custom_text]
    X = pd.concat(frames, axis=1)
 
    return X, np.array(classes), ids
 
def custom_text_features(text):
     
    custom_text_counter = {}
    text_features = ["adult", 
        "antivirus",
        "ascii", 
        "cool", 
        'desiredaccess="FILE_ANY_ACCESS"', 
        '.ex"',
        'flags="FILE_ATTRIBUTE_NORMAL SECURITY_ANONYMOUS"', 
        "free", 
        "HgiXXXy6", 
        "http://www.", 
        "money", 
        "system32",
        "ThunderRT6Main", 
        ".txt", 
        'value="Start Page"', 
        "Warning", 
        "Warning!",
        'terminationtime="00:00.000"',
        'terminationreason="Unknown"',
        'executionstatus="CouldNotInstallHook"',
        'filesize="-1"',
        'username="Administrator"',
        'username="SYSTEM"']
    for text_feature in text_features:
        custom_text_counter["TEXT_" + text_feature] = text.count(text_feature.lower())
        # if custom_text_counter["TEXT_" + text_feature] > 0:
        #     print "Text has:", text_feature
 
    return custom_text_counter
 
def call_feats(tree):
 
    call_counter = {}
    for el in tree.iter(): # el = element
        call = el.tag
        if call not in call_counter:
            call_counter[call] = 0
        else:
            call_counter[call] += 1
 
    # good_calls = ['sleep', 'dump_line']
     
    # call_feat_array = np.zeros(len(good_calls))
    # for i in range(len(good_calls)):
    #     call = good_calls[i]
    #     call_feat_array[i] = 0
    #     if call in call_counter:
    #         call_feat_array[i] = call_counter[call]
 
    # print "call_feat_array", call_feat_array
    # return call_feat_array
    return call_counter
 
def make_matrix(dict):
    """Takes an array of dictionaries and turns it into a Pandas DF matrix."""
    feature_mat = [feature[0] for feature in dict]
    feature_mat = pd.DataFrame(feature_mat)
    feature_mat=feature_mat.fillna(0)
    return feature_mat
 

 
# a function for writing predictions in the required format
def write_predictions(predictions, ids, outfile):
    """
    assumes len(predictions) == len(ids), and that predictions[i] is the
    index of the predicted class with the malware_classes list above for 
    the executable corresponding to ids[i].
    outfile will be overwritten
    """
    with open(outfile,"w+") as f:
        # write header
        f.write("Id,Prediction\n")
        for i, history_id in enumerate(ids):
            f.write("%s,%d\n" % (history_id, predictions[i]))
 

def main():
    X_train_all, t_train_all, train_ids = create_data_matrix(0, num_files, TRAIN_DIR)

    # print "X_train_all.shape", X_train_all.shape
    # print "X_train_all \n", X_train_all

    # split into data and validation set
    # X_train, X_valid, t_train, t_valid = train_test_split(X_train_all, t_train_all, test_size=0, random_state=0)
    
    # ...or don't split them
    X_train = X_train_all
    t_train = t_train_all

    print "X_train shape:", X_train.shape
    print "t_train shape:", t_train.shape
    # print "X_valid shape:", X_valid.shape
    # print "t_valid shape:", t_valid.shape

    # X_valid, t_valid, valid_ids = create_data_matrix(10, 15, TRAIN_DIR)
 
    # print 'Data matrix (training set):', "X_train \n", X_train
    # print 'Classes (training set):', "t_train", t_train
 
    # save to CSV
    X_train.to_csv("X_train.csv")
    np.savetxt("t_train.csv", t_train, delimiter="\n")
 
    # convert DF to numpy array
    X_train = X_train.as_matrix(columns=None)
    # X_valid = X_valid.as_matrix(columns=None)
 
    # train using neural net
    if modelchoice==1:
        nn = Classifier(layers=[Layer("Sigmoid", units=X_train.shape[1]),Layer("Softmax")],learning_rate=0.001,n_iter=100, valid_size=0.2, verbose=1)
    elif modelchoice==2:
        nn = Classifier(layers=[Layer("Sigmoid", units=X_train.shape[1]/8), Layer("Sigmoid", units=X_train.shape[1]/16),Layer("Sigmoid", units=t_train.shape[0]), Layer("Softmax")],n_iter=50,n_stable=10,batch_size=25,learning_rate=0.002, learning_rule="momentum",valid_size=0.2, verbose=1) 
    elif modelchoice==3:
        nn = Classifier(layers=[Layer("Sigmoid", units=X_train.shape[1]),Layer("Sigmoid", units=X_train.shape[1]),Layer("Softmax")],learning_rate=0.001,n_iter=100, valid_size=0.2, verbose=1)
    elif modelchoice==4:
        nn = Classifier(layers=[Layer("Sigmoid", units=X_train.shape[1]),Layer("Softmax")],learning_rate=0.001,n_iter=100, valid_size=0.2, verbose=1)
    elif modelchoice==5:
        nn = Classifier(layers=[Layer("Sigmoid", units=X_train.shape[1]),Layer("Softmax")],learning_rate=0.001,n_iter=100, valid_size=0.2, verbose=1)
    else:
        print("error in defining modelchoice") 

    nn.fit(X_train, t_train)
    # y_pred=nn.predict(X_valid)
    # print(y_pred.shape,"yshape")
    # print(t_train.shape,"train")
    # correct=np.sum(np.equal(y_pred[:,0],t_valid))
    # print(correct,"correct guesses")
    # print float(correct) / float(t_valid.shape[0]) * 100, "accuracy %"
    
###running code
modelchoice=float(sys.argv[1]) 
num_files=float(sys.argv[2])
 
if __name__ == "__main__":
    main()


