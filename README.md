# MINER
### 1. Description
We open source the prototype of MINER. MINER is a REST API fuzzer that utilizes three data-driven designs working together to guide the sequence generation, improve the request generation quality, and capture the unique errors caused by  incorrect parameter usage. 
More details can be found in the prepublication [PDF](https://arxiv.org/abs/2303.02545) (https://arxiv.org/abs/2303.02545). 

### 2. Introduction to Usage
First of all, our code must be placed under the '/home/MINER' path, because we set the absolute path in our code. Of cource, you can can modify the code according to your needs. 
Since we implement the prototype of MINER based on [RESTler](https://github.com/microsoft/restler-fuzzer), the steps to run MINER are the same as [RESTler](https://github.com/microsoft/restler-fuzzer). For instance, you can follow the guidances of [RESTler](https://github.com/microsoft/restler-fuzzer) to generate the grammar, and run the following cmd to start the test. 

```
# /home/MINER/restler_bin_atten/restler/Restler  fuzz --grammar_file /path/to/grammar.py --dictionary_file  /path/to/dict.json --settings /path/to/engine_settings.json --no_ssl  --time_budget  12 
```

### Citation:
```
@inproceedings{lyu2023miner,
  title={MINER: A Hybrid Data-Driven Approach for REST API Fuzzing},
  author={Lyu, Chenyang and Xu, Jiacheng and Ji, Shouling and Zhang, Xuhong and Wang, Qinying and Zhao, Binbin and Pan, Gaoning and Cao, Wei and Chen, Peng and Beyah, Raheem},
  booktitle = {32th {USENIX} Security Symposium ({USENIX} Security 23)},
  year={2023}
}
```
