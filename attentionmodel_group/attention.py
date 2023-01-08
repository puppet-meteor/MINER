import sys
import os
import numpy as np
import random
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch.autograd import Variable
# from torchtext.datasets import Multi30k
# from torchtext.data import Field, BucketIterator, Iterator
from torch.utils.data import DataLoader
# import spacy
import numpy as np
import random
import math
import time
from sklearn.model_selection import train_test_split
import pickle
import datetime

DEC_EMB_DIM = 18
DEC_HID_DIM = 36
ENC_HID_DIM = 36
DEC_DROPOUT = 0.6
BATCH_SIZE = 16
max_length = 20

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


def generate_batch(data_batch):
    src_batch, trg_batch = [], []

    for (raw_de, raw_en) in (data_batch):
        tmp_src_batch = []
        tmp_trg_batch = []
        for token in raw_de:
            tmp_src_batch.append(token)  # (embeddings(Variable(torch.LongTensor([token]))))
        for token in raw_en:
            tmp_trg_batch.append(token)  # (embeddings(Variable(torch.LongTensor([token]))))

        src_batch.append(tmp_src_batch)
        trg_batch.append(tmp_trg_batch)
    src_batch = torch.Tensor(src_batch)
    src_batch = src_batch.long()
    trg_batch = torch.Tensor(trg_batch)
    trg_batch = trg_batch.long()
    src_batch = src_batch.t()
    trg_batch = trg_batch.t()

    return src_batch, trg_batch


class Attention(nn.Module):
    def __init__(self, enc_hid_dim, dec_hid_dim):
        super().__init__()

        self.attn = nn.Linear((enc_hid_dim) + dec_hid_dim, dec_hid_dim)
        self.v = nn.Linear(dec_hid_dim, 1, bias=False)

    def forward(self, hidden, attention_inputs):
        hidden = hidden.to(device)
        attention_inputs = attention_inputs.to(device)
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
        # self.rnn = nn.GRU((enc_hid_dim) + emb_dim, dec_hid_dim)
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
        src = src.to(device)
        trg = trg.to(device)
        batch_size = src.shape[1]
        trg_len = trg.shape[0]

        trg_vocab_size = self.decoder.output_dim

        outputs = torch.zeros(trg_len, batch_size, trg_vocab_size).to(self.device)

        input = src[0, :]
        hidden = (torch.randn(batch_size, DEC_HID_DIM) / 25.0).to(device)
        atten_inputs = (torch.randn(1, batch_size, DEC_HID_DIM) / 25.0).to(device)
        store_hiddens = atten_inputs
        embedding_in_model = 0
        for t in range(1, trg_len):
            if t == 1:
                output, hidden, decoder_hiddens = self.decoder(input, hidden, atten_inputs)
            else:
                output, hidden, decoder_hiddens = self.decoder(input, hidden, atten_inputs)

            outputs[t] = output

            teacher_force = random.random() < teacher_forcing_ratio
            top1 = output.argmax(1)
            input = src[t] if teacher_force else top1
            store_hiddens = torch.cat((store_hiddens, decoder_hiddens), dim=0)
            atten_inputs = store_hiddens

        return outputs


def train(model, iterator, optimizer, criterion, clip, device):
    model.train()
    epoch_loss = 0
    for _, (src, trg) in enumerate(iterator):
        src, trg = src.to(device), trg.to(device)
        optimizer.zero_grad()
        batch_size = src.shape[1]
        output = model(src, trg)
        output_dim = output.shape[-1]
        output = output[1:].view(-1, output_dim)

        trg = trg.reshape((1, len(trg) * batch_size))[0]
        trg = trg[batch_size:]

        loss = criterion(output, trg)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), clip)
        optimizer.step()
        epoch_loss += loss.item()
    return epoch_loss / len(iterator)


def evaluate(model, iterator, criterion):
    model.eval()
    epoch_loss = 0
    with torch.no_grad():
        for _, (src, trg) in enumerate(iterator):
            src, trg = src.to(device), trg.to(device)
            output = model(src, trg, 0)  # turn off teacher forcing
            output_dim = output.shape[-1]
            output = output[1:].view(-1, output_dim)
            batch_size = src.shape[1]
            trg = trg.reshape((1, len(trg) * batch_size))[0]
            trg = trg[batch_size:]

            loss = criterion(output, trg)
            epoch_loss += loss.item()
    return epoch_loss / len(iterator)


def epoch_time(start_time, end_time):
    elapsed_time = end_time - start_time
    elapsed_mins = int(elapsed_time / 60)
    elapsed_secs = int(elapsed_time - (elapsed_mins * 60))
    return elapsed_mins, elapsed_secs


def init_weights(m):
    for name, param in m.named_parameters():
        if 'weight' in name:
            nn.init.normal_(param.data, mean=0, std=0.01)
        else:
            nn.init.constant_(param.data, 0)


dictcount = {}
dictsearch = {}

if __name__ == '__main__':

    starttime = datetime.datetime.now()
    trainingset = pickle.load(open("/home/MINER/restler_bin_atten/trainingset.pkl", 'rb'))

    service_name_list = []
    for case in trainingset:
        if case[2] == 'name=':
            trainingset.remove(case)
    for lyui in range(len(trainingset)):
        # buildup  dictcount
        trainingset[lyui][1] = str(trainingset[lyui][1]) + trainingset[lyui][4]
        if trainingset[lyui][1] not in service_name_list:
            service_name_list.append(trainingset[lyui][1])

        tmpword = ''
        for lyuk in range(len(trainingset[lyui][3])):
            tmpword += trainingset[lyui][3][lyuk]
        tup = (trainingset[lyui][2], tmpword)
        if trainingset[lyui][1] not in dictcount:
            dict1d = {}
            dict1d[tup] = 1
            dictcount[trainingset[lyui][1]] = dict1d
        elif tup not in dictcount[trainingset[lyui][1]]:
            dict1d = dictcount[trainingset[lyui][1]]
            dict1d[tup] = 1
        else:
            dictcount[trainingset[lyui][1]][tup] += 1

    starti = -1
    for lyui in range(len(trainingset)):
        # buildup  dictsearch
        if starti != trainingset[lyui][0]:
            starti = trainingset[lyui][0]
            tmpdict = {}
            requestid = trainingset[lyui][1]
            for lyuj in range(lyui, len(trainingset)):
                if starti != trainingset[lyuj][0]:
                    break
                if requestid != trainingset[lyuj][1]:
                    input("error about requestid")
                if requestid not in dictsearch:
                    dictsearch[requestid] = []
                tmpword = ''
                for lyuk in range(len(trainingset[lyuj][3])):
                    tmpword += trainingset[lyuj][3][lyuk]
                tup = (trainingset[lyuj][2], tmpword)
                if requestid not in tmpdict:
                    tmplist = []
                    tmplist.append(tup)
                    tmpdict[requestid] = tmplist
                elif tup not in tmpdict[requestid]:
                    tmpdict[requestid].append(tup)
            for key1 in tmpdict:
                linedict = {}
                for key2 in tmpdict[key1]:
                    linedict[key2] = dictcount[key1][key2]
                d = sorted(linedict.items(), key=lambda x: x[1], reverse=True)
                linelist = [key for key, value in d]
                dictsearch[key1].append(linelist)

        else:
            continue
        # finish building  dictsearch

    smalllen = 9999999
    largelen = 0
    lenlist = {}
    listword = {}
    for key1 in dictsearch:
        if key1 in listword:
            listword[key1] += 1
        else:
            listword[key1] = 1
        for list1 in dictsearch[key1]:
            # print(list1)
            if len(list1) > largelen:
                largelen = len(list1)
            if len(list1) < smalllen:
                smalllen = len(list1)
            if len(list1) in lenlist:
                lenlist[len(list1)] += 1
            else:
                lenlist[len(list1)] = 1
            for word in list1:
                if word in listword:
                    listword[word] += 1
                else:
                    listword[word] = 1
    print("large: %d" % (largelen))  # 35
    print("small: %d" % (smalllen))  # 1

    np.save('/home/MINER/attentionmodel_group/listword.npy', listword)
    word_to_ix = {}
    max_length = largelen + 1

    with open("/home/MINER/attentionmodel_group/service_name_list.pkl", 'wb') as f:
        pickle.dump(service_name_list, f, pickle.HIGHEST_PROTOCOL)

    # retraining model
    d = sorted(listword.items(), key=lambda x: x[1], reverse=True)
    listwordsort = [key for key, value in d]
    count1 = 1
    for key1 in listwordsort:
        word_to_ix[key1] = count1
        count1 = count1 + 1
    np.save('/home/MINER/attentionmodel_group/word_to_ix.npy', word_to_ix)

    #  train the model, saving the parameters that give the best validation loss.
    wordlength = len(word_to_ix)
    embeddings = nn.Embedding(wordlength + 1, DEC_EMB_DIM, padding_idx=0)
    torch.save(embeddings, '/home/MINER/attentionmodel_group/embedding.pt')

    # training data build

    traindata = []
    for key1 in dictsearch:
        for list1 in dictsearch[key1]:
            tmplist = [word_to_ix[key1]]
            count = 0
            for word1 in list1:
                tmplist.append(word_to_ix[word1])
                count += 1
            if count >= max_length:
                input("error length")
            while count < max_length:
                tmplist.append(0)
                count += 1

            traindata.append(tmplist)

    train_index, val_index = train_test_split(np.arange(len(traindata)), test_size=0.2, random_state=33)
    count = 0
    train_data = []
    for idx in train_index:

        src = []
        trg = []
        count = 0
        while count < max_length:
            if count == 0:
                src = [traindata[idx][count]]
                trg = [traindata[idx][count + 1]]

            else:
                src.append(traindata[idx][count])
                trg.append(traindata[idx][count + 1])
            count += 1

        train_data.append((src, trg))
        count += 1

    count = 0
    valid_data = []
    for idx in val_index:
        src = []
        trg = []
        count = 0
        while count < max_length:
            if count == 0:
                src = [traindata[idx][count]]
                trg = [traindata[idx][count + 1]]
            else:
                src.append(traindata[idx][count])
                trg.append(traindata[idx][count + 1])
            count += 1

        valid_data.append((src, trg))
        count += 1

    train_iterator = DataLoader(train_data, batch_size=BATCH_SIZE,
                                shuffle=True, collate_fn=generate_batch)
    valid_iterator = DataLoader(valid_data, batch_size=BATCH_SIZE,
                                shuffle=True, collate_fn=generate_batch)

    # model build
    attn = Attention(ENC_HID_DIM, DEC_HID_DIM)
    dec = Decoder(wordlength + 1, DEC_EMB_DIM, DEC_HID_DIM, DEC_HID_DIM, DEC_DROPOUT, attn, embeddings)
    model = attnLSTM(dec, device).to(device)
    model.apply(init_weights)

    optimizer = optim.Adam(model.parameters(), weight_decay=5e-05, lr=15e-4)  # , lr=0.0001, eps=1e-08, weight_decay=0)

    model = model.to(device)

    criterion = nn.CrossEntropyLoss()

    N_EPOCHS = 27
    CLIP = 1
    best_valid_loss = float('inf')

    for epoch in range(N_EPOCHS):
        torch.manual_seed(1)
        start_time = time.time()
        train_loss = train(model, train_iterator, optimizer, criterion, CLIP, device)
        valid_loss = evaluate(model, valid_iterator, criterion)
        end_time = time.time()
        epoch_mins, epoch_secs = epoch_time(start_time, end_time)
        if valid_loss < best_valid_loss:
            best_valid_loss = valid_loss
            torch.save(model, '/home/MINER/attentionmodel_group/apifuzzmodel.pt')
            torch.save(model.decoder.embedding, 'embedding.pt')
        print(f'Epoch: {epoch + 1:02} | Time: {epoch_mins}m {epoch_secs}s')
        print(f'\tTrain Loss: {train_loss:.3f} | Train PPL: {math.exp(train_loss):7.3f}')
        print(f'\t Val. Loss: {valid_loss:.3f} |  Val. PPL: {math.exp(valid_loss):7.3f}')

    print("training time: " + str((datetime.datetime.now() - starttime).seconds))
