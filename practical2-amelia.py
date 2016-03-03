# Example Feature Extraction from XML Files
# We count the number of specific system calls made by the programs, and use
# these as our features.

# This code requires that the unzipped training set is in a folder called "train". 

import os
from collections import Counter
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
import numpy as np
from scipy import sparse
import pandas
import util
from sknn.mlp import Regressor, Layer, Classifier

TRAIN_DIR = "train"

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
        print "datafile", datafile
        if datafile == '.DS_Store':
            continue

        # print "i", i

        i += 1
        if i < start_index:
            continue 
        if i >= end_index:
            break

        # extract id and true class (if available) from filename
        id_str, clazz = datafile.split('.')[:2]
        ids.append(id_str)

        # print "ids", ids

        # add target class if this is training data
        try:
            classes.append(util.malware_classes.index(clazz))

        except ValueError:
            # we should only fail to find the label in our list of malware classes
            # if this is test data, which always has an "X" label
            assert clazz == "X"
            classes.append(-1)

        # print "classes", classes

        # parse file as an xml document
        tree = ET.parse(os.path.join(direc,datafile))
        add_to_set(tree)

        # print "tree", tree

        this_row = call_feats(tree)
        if X_calls is None: # if X is empty
            X_calls = this_row 
        else:
            X_calls = np.vstack((X_calls, this_row))

        # parse files as text files
        with open("train/"+ datafile, "r") as myfile:
            text = myfile.read()
        this_row = custom_text_features(text)
        if X_custom_text is None: # if X is empty
            X_custom_text = this_row 
        else:
            X_custom_text = np.vstack((X_custom_text, this_row))

    # turn arrays of dicts into Pandas DFs
    X_calls = make_matrix(X_calls)
    X_custom_text = make_matrix(X_custom_text)

    print "X_calls", X_calls
    print "X_custom_text \n", X_custom_text
    print "X_custom_text.shape", X_custom_text.shape

    # return X, np.array(classes), ids

def custom_text_features(text):
    
    custom_text_counter = {}
    text_features = ["hash_error"]
    for text_feature in text_features:
        custom_text_counter["text_" + text_feature] = text.count(text_feature)

    print "custom_text_counter", custom_text_counter
    return custom_text_counter

def call_feats(tree):

    call_counter = {}
    for el in tree.iter(): # el = element
        # print "el", el
        call = el.tag
        # print "call", call
        if call not in call_counter:
            call_counter[call] = 0
        else:
            call_counter[call] += 1
        # print "call_counter", call_counter

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

def make_matrix(array):
    """Takes an array of dictionaries and turns it into a Pandas DF matrix."""
    feature_mat = [feature[0] for feature in array]
    feature_mat = pandas.DataFrame(feature_mat)
    feature_mat=feature_mat.fillna(0)
    return feature_mat

def main():
    # X_train, t_train, train_ids = create_data_matrix(0, 10, TRAIN_DIR)
    X_train, t_train, train_ids = create_data_matrix(0, 3, TRAIN_DIR)
    # X_valid, t_valid, valid_ids = create_data_matrix(10, 15, TRAIN_DIR)

    # print 'Data matrix (training set):', "X_train", X_train
    # print 'Classes (training set):', "t_train", t_train
    print "Number of files processed:", len(t_train)

    # # train using neural net
    # nn = Classifier(
    # layers=[
    #     Layer("Rectifier", units=feature_mat.shape[1]),
    #     Layer("Softmax")],
    # learning_rate=0.02,
    # n_iter=10)
    # nn.fit(X_train, t_train)
    # nn.predict(X_train)

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

if __name__ == "__main__":
    main()
    