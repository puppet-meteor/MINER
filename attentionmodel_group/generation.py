import sys
import os
import numpy as np
import random
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch.autograd import Variable
from torch.utils.data import DataLoader
# import spacy
import numpy as np
import random
import math
import time
from sklearn.model_selection import train_test_split
import datetime
import pickle

max_length = 20
hiddenlyu = 36

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


class Attention(nn.Module):
    def __init__(self, enc_hid_dim, dec_hid_dim):
        super().__init__()

        self.attn = nn.Linear((enc_hid_dim) + dec_hid_dim, dec_hid_dim)
        self.v = nn.Linear(dec_hid_dim, 1, bias=False)

    def forward(self, hidden, attention_inputs):
        src_len = attention_inputs.shape[0]
        if src_len == 1:
            hidden = hidden.unsqueeze(1)
            attention_inputs = attention_inputs.permute(1, 0, 2)
            energy = torch.tanh(self.attn(torch.cat((hidden, attention_inputs), dim=2)))
            attention = self.v(energy).squeeze(2)
            return F.softmax(attention, dim=1)
        else:
            hidden = hidden.unsqueeze(1).repeat(1, src_len, 1)
            attention_inputs = attention_inputs.permute(1, 0, 2)

            energy = torch.tanh(self.attn(torch.cat((hidden, attention_inputs), dim=2)))
            attention = self.v(energy).squeeze(2)
            return F.softmax(attention, dim=1)


class Decoder(nn.Module):
    def __init__(self, output_dim, emb_dim, enc_hid_dim, dec_hid_dim, dropout, attention, embeddings):
        super().__init__()

        self.output_dim = output_dim
        self.attention = attention
        self.embedding = embeddings  # nn.Embedding(output_dim, emb_dim)
        self.rnn = nn.GRU(emb_dim, dec_hid_dim)
        self.fc_out = nn.Linear((enc_hid_dim) + dec_hid_dim + emb_dim, output_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, input, hidden, atten_inputs):
        input = input.to(device)
        hidden = hidden.to(device)
        atten_inputs = atten_inputs.to(device)
        input = input.unsqueeze(0)
        embedded = self.dropout(self.embedding(input))

        output, hidden = self.rnn(embedded, hidden.unsqueeze(0))
        a = self.attention(hidden.squeeze(0), atten_inputs)
        a = a.unsqueeze(1)
        atten_inputs = atten_inputs.permute(1, 0, 2)
        weighted = torch.bmm(a, atten_inputs)
        weighted = weighted.permute(1, 0, 2)

        embedded = embedded.squeeze(0)
        output = output.squeeze(0)
        weighted = weighted.squeeze(0)

        prediction = self.fc_out(torch.cat((output, weighted, embedded), dim=1))
        return prediction, hidden.squeeze(0), hidden


class attnLSTM(nn.Module):
    def __init__(self, decoder, device):
        super().__init__()

        self.decoder = decoder
        self.device = device

    def forward(self, src, trg, teacher_forcing_ratio=0.5):
        batch_size = src.shape[1]
        trg_len = trg.shape[0]

        trg_vocab_size = self.decoder.output_dim

        # tensor to store decoder outputs
        outputs = torch.zeros(trg_len, batch_size, trg_vocab_size).to(self.device)

        # first input to the decoder is the <sos> tokens
        input = src[0, :]
        hidden = torch.zeros(batch_size, DEC_HID_DIM)
        atten_inputs = torch.zeros(1, batch_size, DEC_HID_DIM)
        store_hiddens = atten_inputs
        for t in range(1, trg_len):
            if t == 1:
                output, hidden, decoder_hiddens = self.decoder(input, hidden, atten_inputs)
            else:
                output, hidden, decoder_hiddens = self.decoder(input, hidden, atten_inputs)

            outputs[t] = output

            # decide if we are going to use teacher forcing or not
            teacher_force = random.random() < teacher_forcing_ratio
            # get the highest predicted token from our predictions
            top1 = output.argmax(1)
            # if teacher forcing, use actual next token as next input
            # if not, use predicted token
            input = src[t] if teacher_force else top1
            store_hiddens = torch.cat((store_hiddens, decoder_hiddens), dim=0)
            atten_inputs = store_hiddens

        return outputs


def generation(service_name, decoder, device):
    hidden = ((torch.randn(1, hiddenlyu)) / 25.0).to(
        device)  # (batch_size, DEC_HID_DIM)   #atten_inputs = torch.zeros(1, batch_size, DEC_HID_DIM)
    atten_inputs = ((torch.randn(1, 1, hiddenlyu)) / 25.0).to(device)  # (1, batch_size, DEC_HID_DIM )
    store_hiddens = atten_inputs
    trg_vocab_size = decoder.output_dim
    outputs = torch.zeros(max_length, 1, trg_vocab_size).to(device)
    top_list = []
    input = torch.tensor([service_name])
    t = 0
    while 1:
        output, hidden, decoder_hiddens = decoder(input, hidden, atten_inputs)

        outputs[t] = output
        t = t + 1
        if t >= max_length - 1:
            break
        tmpoutput = output
        top1 = tmpoutput.argmax(1)
        for i1 in range(1, 5):
            top1 = tmpoutput.argmax(1)
            if int(top1) not in top_list:
                break
            tmpoutput[0][int(top1)] = min(tmpoutput[0])
        top_list.append(int(top1))
        if int(top1) == 0:
            break
        input = top1
        store_hiddens = torch.cat((store_hiddens, decoder_hiddens), dim=0)
        atten_inputs = store_hiddens

    return outputs


if __name__ == '__main__':
    starttime = datetime.datetime.now()
    word_to_ix = {}
    word_to_ix = np.load('/home/MINER/attentionmodel_group/word_to_ix.npy', allow_pickle=True)
    word_to_ix = word_to_ix.item()
    ix_to_word = {}

    for key1 in word_to_ix:
        ix_to_word[word_to_ix[key1]] = key1

    # embeddings = torch.load('embedding.pt')
    if os.path.exists('/home/MINER/attentionmodel_group/apifuzzmodel.pt') == True:
        model = torch.load('/home/MINER/attentionmodel_group/apifuzzmodel.pt')

    decoder = model.decoder
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    torch.set_grad_enabled(False)

    service_name_list = []
    if os.path.exists("/home/MINER/attentionmodel_group/service_name_list.pkl") == True:
        service_name_list = pickle.load(open("/home/MINER/attentionmodel_group/service_name_list.pkl", 'rb'))
    else:
        trainingset = pickle.load(open("/home/MINER/restler_bin_atten/trainingset.pkl", 'rb'))
        for lyui in range(len(trainingset)):
            tmpservice_name = str(trainingset[lyui][1]) + trainingset[lyui][4]
            if tmpservice_name not in service_name_list:
                service_name_list.append(tmpservice_name)
        with open("/home/MINER/attentionmodel_group/service_name_list.pkl", 'wb') as f:
            pickle.dump(service_name_list, f, pickle.HIGHEST_PROTOCOL)

    listword = np.load('/home/MINER/attentionmodel_group/listword.npy', allow_pickle=True)
    listword = listword.tolist()
    d = sorted(listword.items(), key=lambda x: x[1], reverse=True)
    listwordsort = [key for key, value in d]

    dictoutput = {}
    for lyui in range(len(service_name_list)):
        service_name = service_name_list[lyui]
        if service_name not in dictoutput:
            tmplist = []
            dictoutput[service_name] = tmplist
        for i in range(200):
            outputss = generation(word_to_ix[service_name], decoder, device)

            toplist = []
            toplist2 = []
            totaltop = []

            for t in range(len(outputss)):
                tmpoutput = outputss[t]

                top1 = int(tmpoutput.argmax(1))
                for i2 in range(0, 10):
                    top1 = int(tmpoutput.argmax(1))
                    # add more randomness
                    if random.random() < 0.03:
                        tmpoutput[0][int(top1)] = min(tmpoutput[0])
                        continue
                    # add more randomness
                    if top1 == 0:
                        break
                    if top1 not in toplist:
                        break
                    tmpoutput[0][int(top1)] = min(tmpoutput[0])

                toplist.append(top1)
                if top1 not in toplist2:
                    toplist2.append(top1)
                totaltop.append(int(outputss[t].argmax(1)))

            mutationlist = []
            for t in range(len(outputss)):
                top1 = toplist2[t]

                if int(top1) == 0:
                    break
                mutationlist.append(ix_to_word[int(top1)])

            mutationlist = [x for _, x in sorted(zip([listwordsort.index(x) for x in mutationlist], mutationlist))]
            if mutationlist != [] and mutationlist not in dictoutput[service_name]:
                dictoutput[service_name].append(mutationlist)

    # print("\n\nmutationlist:\n\n"+ str(dictoutput))

    for key1 in dictoutput.keys():
        print("\n " + str(key1) + "  " + str(len(dictoutput[key1])))

    with open("/home/MINER/restler_bin_atten/mutationlist.pkl", "wb") as f:
        pickle.dump(dictoutput, f, pickle.HIGHEST_PROTOCOL)
    print("generation time: " + str((datetime.datetime.now() - starttime).seconds))
