# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import inspect
import struct

# 调用之前封装好的两个类
from .bytevector import ByteVector
from . import opcodes

from .. import coins
from .. import protocol
from .. import util

# format这个类相当重要，是调用Txin、Txout的必须的一部分
from ..protocol import format

# 对外暴露两个类接口
__all__ = ['Script', 'Tokenizer']

# Convenient constants
# 这是为了全局定义
Zero = ByteVector.from_value(0)
One = ByteVector.from_value(1)


# ————————————————————工具类函数———————————————————————

# check whether the opcode is a publickey for P2PK
def _is_pubkey(opcode, bytes, data) -> bool:
    if opcode != Tokenizer.OP_LITERAL:
        return False
    if len(data) != 65 or data[0] != chr(0x04):
        return False
    return True


# check whether the opcode is a hash160 value for P2PKH
def _is_hash160(opcode, bytes, data) -> bool:
    if opcode != Tokenizer.OP_LITERAL:
        return False
    if len(data) != 20:
        return False
    return True


def _is_hash256(opcode, bytes, data) -> bool:
    if opcode != Tokenizer.OP_LITERAL:
        return False
    if len(data) != 32:
        return False
    return True


# —————————————————————脚本验证模板——————————————————————

SCRIPT_FORM_NON_STANDARD = 'non-standard'
SCRIPT_FORM_PAY_TO_PUBKEY_HASH = 'pay-to-pubkey-hash'  # P2PKH
SCRIPT_FORM_PAY_TO_PUBKEY = 'pay-to-pubkey'  # P2PK
SCRIPT_FORM_UNSPENDABLE = 'unspendable'
SCRIPT_FORM_ANYONE_CAN_SPEND = 'anyone-can-spend'
SCRIPT_FORM_TRANSACTION_PUZZLE_HASH256 = 'transaction-puzzle-hash256'

# 标准脚本模式，为下面验证是否为标准脚本做验证
STANDARD_SCRIPT_FORMS = [
    SCRIPT_FORM_PAY_TO_PUBKEY_HASH,
    SCRIPT_FORM_PAY_TO_PUBKEY
]

# @TODO: outdated documentation
# Templates are (name, template) tuples. Each template is a tuple of
# (callable, item1, item2, ...) where callable is called on the entrie
# tokenized script; itemN can be either an opcode or a callable which
# accepts (opcode, bytes, value).


# 这是P2PKH的模板方法，也就是对应的解锁脚本
TEMPLATE_PAY_TO_PUBKEY_HASH = (lambda t: len(t) == 5, opcodes.OP_DUP,
                               opcodes.OP_HASH160, _is_hash160, opcodes.OP_EQUALVERIFY,
                               opcodes.OP_CHECKSIG)

# 这是P2PK的模板方法，也就是对应的解锁脚本
TEMPLATE_PAY_TO_PUBKEY = (lambda t: len(t) == 2, _is_pubkey,
                          opcodes.OP_CHECKSIG)

# 将对应模板载入字典，方便直接查询
Templates = [

    (SCRIPT_FORM_PAY_TO_PUBKEY_HASH, TEMPLATE_PAY_TO_PUBKEY_HASH),

    (SCRIPT_FORM_PAY_TO_PUBKEY, TEMPLATE_PAY_TO_PUBKEY),

    #    (SCRIPT_FORM_UNSPENDABLE,
    #     (lambda t: True,
    #      opcodes.OP_RETURN, )),

    #    (SCRIPT_FORM_ANYONE_CAN_SPEND,
    #     (lambda t: len(t) == 0, )),

    #    (SCRIPT_FORM_TRANSACTION_PUZZLE_HASH256,
    #     (lambda t: len(t) == 3,
    #      opcodes.OP_HASH256, _is_hash256, opcodes.OP_EQUAL)),
]


# ——————————————————————栈操作命令—————————————————————————

# 进行栈命令操作(func指定)
def _stack_op(stack, func) -> bool:
    '''Replaces the top N items from the stack with the items in the list
       returned by the callable func; N is func's argument count.

       The result must return a list.

       False is returned on error, otherwise True.'''

    # not enough arguments 参数不足
    count = len(inspect.getfullargspec(func).args)
    if len(stack) < count:
        return False

    # 取下标最后一个值，即出栈
    args = stack[-count:]
    stack[-count:] = []

    # 将栈命令附带的参数传入
    # add each returned item onto the stack
    for item in func(*args):
        stack.append(item)

    return True


# 进行栈数学操作(func指定)
def _math_op(stack, func, check_overflow=True) -> bool:
    '''Replaces the top N items from the stack with the result of the callable
       func; N is func's argument count.

       A boolean result will push either a 0 or 1 on the stack. None will push
       nothing.

       Otherwise, the result must be a ByteVector!!!

       False is returned on error, otherwise True.'''

    # 栈内的操作必须是一个ByteVector或者0，1结果

    # not enough arguments
    count = len(inspect.getfullargspec(func).args)
    if len(stack) < count: return False
    args = stack[-count:]
    stack[-count:] = []

    # 同时操作的参数不能超过4个
    # check for overflow
    if check_overflow:
        for arg in args:
            if len(arg) > 4:
                return False

    # compute the result
    result = func(*args)

    # convert booleans to One or Zero
    if result == True:
        result = One
    elif result == False:
        result = Zero

    if result is not None:
        stack.append(result)

    return True


# 栈值哈希操作(func指定)
def _hash_op(stack, func) -> bool:
    '''Replaces the top of the stack with the result of the callable func.

       The result must be a ByteVector.

       False is returned on error, otherwise True.'''

    # not enough arguments
    if len(stack) < 1:
        return False

    # hash and push
    value = func(stack.pop().vector)
    stack.append(ByteVector(value))

    return True


# ————————————————————输出再签名过程—————————————————————————

# 检查签名过程(func指定)，可以重新指定输出问题

# hash_type字段是接在交易后面有一系列编码过程，详情参见笔记内容

def check_signature(signature, public_key, hash_type, subscript, transaction, input_index) -> bool:

    # figure out the hash_type and adjust the signature
    if hash_type == 0:
        hash_type = ord(signature[-1])
    if hash_type != ord(signature[-1]):
        raise Exception('@todo: should I check for this?')
    signature = signature[:-1]
    # 尾部出栈 去掉sig_hash部分内容

    # print hash_type

    # 先确定签名的类型

    # 影响交易输出

    # 这是被之前使用的一种常用方法
    # SIGHASH_ALL
    if (hash_type & 0x1f) == 0x01 or hash_type == 0:
        # print "ALL"
        # 构建输入信息
        tx_ins = []
        for (index, tx_in) in enumerate(transaction.inputs):
            script = ''
            if index == input_index:
                script = subscript

            tx_in = protocol.TxnIn(tx_in.previous_output, script, tx_in.sequence)
            tx_ins.append(tx_in)

        tx_outs = transaction.outputs

        # 到这里输入tx_ins全部封装完成
        # tx_outs用的是transcation自带的类方法

    # SIGHASH_NONE (other tx_in.sequence = 0, tx_out = [ ])
    elif (hash_type & 0x1f) == 0x02:
        # print "NONE"
        # 构建输入信息
        tx_ins = []
        index = 0
        for tx_in in transaction.inputs:
            script = ''
            sequence = 0
            if index == input_index:
                script = subscript
                sequence = tx_in.sequence
            index += 1

            tx_in = protocol.TxnIn(tx_in.previous_output, script, sequence)
            tx_ins.append(tx_in)

        tx_outs = []

    # SIGHASH_SINGLE (len(tx_out) = input_index + 1, other outputs = (-1, ''), other tx_in.sequence = 0)
    elif (hash_type & 0x1f) == 0x03:
        # print "SINGLE"
        # 构建输入信息
        tx_ins = []
        index = 0
        for tx_in in transaction.inputs:
            script = ''
            sequence = 0
            if index == input_index:
                script = subscript
                sequence = tx_in.sequence
            index += 1

            tx_in = protocol.TxnIn(tx_in.previous_output, script, sequence)
            tx_ins.append(tx_in)

        tx_outs = []
        index = 0
        for tx_out in transaction.outputs:
            if len(tx_outs) > input_index: break
            if index != input_index:
                tx_out = protocol.TxnOut(-1, '')
            tx_outs.append(tx_out)
            index += 1

    else:
        raise Exception('unknown hash type: %d' % hash_type)

    # 这个和上面三种必须共同使用
    # 该修饰符表示签名时只签正在被签名的输入本身，其他输入不在签名范围内，anyone can pay，who cares

    # SIGHASH_ANYONECANPAY
    if (hash_type & 0x80) == 0x80:
        # print "ANYONE"
        tx_in = transaction.inputs[input_index]
        tx_ins = [protocol.TxnIn(tx_in.previous_output, subscript, tx_in.sequence)]

        tx_outs = transaction.outputs

    # FlexTxn可以成为容器Txn，是用来重新封装Txn使用的
    tx_copy = FlexTxn(transaction.version, tx_ins, tx_outs, transaction.lock_time)

    # compute the data to verify
    # pack(fmt, v1, v2, ...)  ------ 根据所给的fmt描述的格式将值v1，v2，...转换为一个字符串。I对应unsigned int
    # 生成新的签名哈希
    sig_hash = struct.pack('<I', hash_type)

    # 这一步是在最后一步在签名之后加上hash_type内容，即可完成签名过程
    payload = tx_copy.binary() + sig_hash

    # verify the data
    # print "PK", public_key.encode('hex')
    # print "S", signature.encode('hex'), input_index
    # print "T", transaction
    # print "I", input_index

    # payload是data，输出验证过程
    return util.ecc.verify(payload, public_key, signature)


# identical to protocol.Txn except it allows zero tx_out for SIGHASH_NONE
# 与protocol.Txn相同，即重新包装输出的意思
# 封装输出信息的过程，之前系统的设计是直接封装约等于SIGHASH_ALL
class FlexTxn(protocol.Txn):
    properties = [
        ('version', format.FormatTypeNumber('I')),
        ('tx_in', format.FormatTypeArray(format.FormatTypeTxnIn, 1)),
        ('tx_out', format.FormatTypeArray(format.FormatTypeTxnOut)),
        ('lock_time', format.FormatTypeNumber('I')),
    ]


# ————————————————————产生解锁tokens——————————————————————————

class Tokenizer(object):
    # 这里说的已经很清楚了，就是将脚本的值，具体化为一个tokens类型

    # >>> import pycoind
    #
    # >>>  # txid: 370b0e8298cf00b47a61ebac3381d38f38f62b065ef5d8dd3cfd243e4b6e9137 (input# 0)
    # >>> pk_script = 'v\xa9\x14\xd6Kqr\x9aPM#\xd9H\x88\xd3\xf7\x12\xd5WS\xd5\xd6"\x88\xac'
    # >>> print
    # pycoind.Tokenizer(pk_script)
    # OP_DUP OP_HASH160 d64b71729a504d23d94888d3f712d55753d5d622 OP_EQUALVERIFY OP_CHECKSIG

    '''Tokenizes a script into tokens.

       Literals can be accessed with get_value and have the opcode 0x1ff.

       The *VERIFY opcodes are expanded into the two equivalent opcodes.'''

    OP_LITERAL = 0x1ff

    def __init__(self, script, expand_verify=False):
        self._script = script
        self._expand_verify = expand_verify
        self._tokens = []
        self._process(script)

    def append(self, script):
        self._script += script  # 直接添加
        self._process(script)  # 直接添加tokens.append()

    # 原始tokens就是一个包含(opcode, bytes, value)三元组的list，这个函数是为了获取tokens里面的值转化为字符串
    # 示例：
    # pycoind.Tokenizer(pk_script)
    # OP_DUP OP_HASH160 d64b71729a504d23d94888d3f712d55753d5d622 OP_EQUALVERIFY OP_CHECKSIG
    def get_subscript(self, start_index=0, filter=None) -> str:
        '''Rebuild the script from token start_index, using the callable
           removing tokens that return False for filter(opcode, bytes, value)
           where bytes is the original bytes and value is any literal value.'''
        # 从开始的坐标重建脚本，并且检查所有脚本是否满足filter格式检查

        # tokens里面内置的是一个三元组！！：(opcode,bytes,value)三个部分都存在
        output = ''
        for (opcode, bytes, value) in self._tokens[start_index:]:
            # 不符合形式的就不添加
            if filter and not filter(opcode, bytes, value):
                continue
            output += bytes
        return output

    # 验证脚本属于哪一种验证方式
    def match_template(self, template) -> bool:
        ' Given a template, return True if this script matches. '

        if not template[0](self):
            return False

        # ((opcode, bytes, value), template_target)
        for ((o, b, v), t) in zip(self._tokens, template[1:]):

            # callable, check the value
            if callable(t):
                if not t(o, b, v):
                    return False

            # otherwise, compare opcode
            elif t != o:
                return False

        return True

    # 用来验证末位操作码的map
    _Verify = {
        opcodes.OP_EQUALVERIFY: opcodes.OP_EQUAL,
        opcodes.OP_NUMEQUALVERIFY: opcodes.OP_NUMEQUAL,
        opcodes.OP_CHECKSIGVERIFY: opcodes.OP_CHECKSIG,
        opcodes.OP_CHECKMULTISIGVERIFY: opcodes.OP_CHECKMULTISIG,
    }

    # 真正的脚本处理过程
    def _process(self, script):
        'Parse the script into tokens. Internal use only.'
        # 解析脚本为tokens，私有方法

        while script: # 循环直到script值为空
            opcode = ord(script[0])
            bytes = script[0]
            # 截取脚本
            script = script[1:]
            value = None

            verify = False

            if opcode == opcodes.OP_0:
                value = Zero
                opcode = Tokenizer.OP_LITERAL

            # 截取指定长度的字符，因为这是push_data的操作
            elif 1 <= opcode <= 78:
                length = opcode

                if opcodes.OP_PUSHDATA1 <= opcode <= opcodes.OP_PUSHDATA4:
                    op_length = [1, 2, 4][opcode - opcodes.OP_PUSHDATA1] # 找出是哪一种pushdata的方式以及计算push的字节数
                    format = ['<B', '<H', '<I'][opcode - opcodes.OP_PUSHDATA1]
                    length = struct.unpack(format, script[:op_length])[0]
                    bytes += script[:op_length]
                    script = script[op_length:] # 截取pushdata的指定部分

                value = ByteVector(vector=script[:length])
                bytes += script[:length]
                script = script[length:]
                if len(value) != length:
                    raise Exception('not enought script for literal')
                opcode = Tokenizer.OP_LITERAL

            elif opcode == opcodes.OP_1NEGATE:
                opcode = Tokenizer.OP_LITERAL
                value = ByteVector.from_value(-1)

            elif opcode == opcodes.OP_TRUE:
                opcode = Tokenizer.OP_LITERAL
                value = ByteVector.from_value(1)

            elif opcodes.OP_1 <= opcode <= opcodes.OP_16:
                value = ByteVector.from_value(opcode - opcodes.OP_1 + 1)
                opcode = Tokenizer.OP_LITERAL

            elif self._expand_verify and opcode in self._Verify:
                opcode = self._Verify[opcode]
                verify = True

            self._tokens.append((opcode, bytes, value))

            if verify:
                self._tokens.append((opcodes.OP_VERIFY, '', None))

    # 获取开始的字符
    def get_bytes(self, index) -> bytes:
        'Get the original bytes used for the opcode and value'

        return self._tokens[index][1]

    # 获取开始的值
    def get_value(self, index) -> str:
        'Get the value for a literal.'

        return self._tokens[index][2]

    def __len__(self):
        return len(self._tokens)

    def __getitem__(self, name):
        return self._tokens[name][0]

    def __iter__(self):
        for (opcode, bytes, value) in self._tokens:
            yield opcode

    def __str__(self):
        output = []
        for (opcode, bytes, value) in self._tokens:
            if opcode == Tokenizer.OP_LITERAL:
                output.append(value.vector.encode('hex'))
            else:
                if bytes:
                    output.append(opcodes.get_opcode_name(ord(bytes[0])))

        return " ".join(output)


# ——————————————————————真正的脚本验证操作————————————————————

# 采用一个基于栈的逆波兰表达式进行
class Script(object):
    def __init__(self, transaction, coin=coins.Bitcoin):
        self._transaction = transaction
        self._coin = coin

    @property
    # 计算有多少个交易
    def output_count(self) -> int:
        return len(self._transaction.outputs)

    # 计算输出地址的格式
    def output_address(self, output_index) -> str:

        # 交易输出中获取脚本值
        pk_script = self._transaction.outputs[output_index].pk_script
        # 解析出tokens
        tokens = Tokenizer(pk_script)

        # 验证输出的锁定脚本是哪种验证方式，并将输出地址按照模板整合的过程，搞定输出的锁定脚本
        if tokens.match_template(TEMPLATE_PAY_TO_PUBKEY_HASH):
            pubkeyhash = tokens.get_value(2).vector
            return util.key.pubkeyhash_to_address(pubkeyhash, self._coin.address_version)

        if tokens.match_template(TEMPLATE_PAY_TO_PUBKEY):
            pubkey = tokens.get_value(0).vector
            return util.key.publickey_to_address(pubkey, self._coin.address_version)

        return None

    # def previous_output(self, index):
    #    po = self._transaction.tx_in[index].previous_output
    #    return (po.hash, po.index)

    # 确认解锁脚本的来源（P2PKH还是P2PK）
    def script_form(self, output_index) -> str:
        pk_script = self._transaction.outputs[output_index].pk_script
        tokens = Tokenizer(pk_script)
        for (sf, template) in Templates:
            if tokens.match_template(template):
                return sf
        return SCRIPT_FORM_NON_STANDARD

    # 检查脚本是否标准
    def is_standard_script(self, output_index) -> bool:
        pk_script = self._transaction.outputs[output_index]
        tokens = Tokenizer(pk_script, expand_verify=False)
        for sf in STANDARD_SCRIPT_FORMS:
            if tokens.match_template(Templates[sf]):
                return True
        return False

    @property
    # 计算传入交易的个数
    def input_count(self) -> int:
        return len(self._transaction.inputs)

    # 验证某个输入：（输入坐标，脚本）
    def verify_input(self, input_index, pk_script) -> bool:
        input = self._transaction.inputs[input_index]

        # 参数：输入签名脚本，公钥脚本，交易，坐标

        # ——————————————————————这是process！！！！！！！！！！！！！！！！！！！！————————————————————————

        # 他这儿搞了一个前向输出的脚本，这个简单，直接使用固定字段就可以。
        return self.process(input.signature_script, pk_script, self._transaction, input_index)

    def verify(self) -> bool:
        '''Return True if all transaction inputs can be verified against their
           previous output.'''

        # 遍历所有输入的过程
        for i in range(0, len(self._transaction.inputs)):

            # ignore coinbase (generation transaction input)第一个位置不检查输入，后面输入是本次的输出
            if self._transaction.index == 0 and i == 0: continue

            # verify the input with its previous output
            input = self._transaction.inputs[i]
            previous_output = self._transaction.previous_output(i) # 只要取得前向输入就可以
            if not self.verify_input(i, previous_output.pk_script):
                # print "INVALID:", self._transaction.hash.encode('hex'), i
                return False

        return True

    @staticmethod
    def process(signature_script, pk_script, transaction, input_index, hash_type=0):

        # tokenize (placing the last code separator after the signature script)
        # 先将签名脚本（即input.signature_script）token化，并加入锁定脚本
        tokens = Tokenizer(signature_script, expand_verify=True)
        signature_length = len(tokens)
        # 再加入公钥脚本（即previous_output.pk_script），准备进行解锁操作
        # 这一部分script不需要重新计算，append方法会自动计算
        tokens.append(pk_script)

        # 这个属性等于签名长度，而签名长度又等于tokens的长度
        last_codeseparator = signature_length

        # print str(tokens)

        # check for VERY forbidden opcodes (see "reserved Words" on the wiki)
        for token in tokens:
            if token in (opcodes.OP_VERIF, opcodes.OP_VERNOTIF):
                return False

        # stack of entered if statments' condition values
        ifstack = []

        # operating stacks
        # 初始化计算栈和调用栈
        stack = []
        altstack = []

        # ！！！开始解锁过程！！！
        for pc in range(0, len(tokens)):# 计数过程

            # 取出脚本的操作码
            opcode = tokens[pc]

            # print "STACK:", (opcodes.OPCODE_NAMES[min(opcode, 255)], repr(tokens.get_value(pc)))
            # print "  " + "\n  ".join("%s (%d)" % (i.vector.encode('hex'), i.value) for i in stack)
            # print

            # handle if before anything else 首先检查交易是否被终止
            if opcode == opcodes.OP_IF: # 栈顶元素为0将被执行
                ifstack.append(stack.pop().value != 0)

            elif opcode == opcodes.OP_NOTIF: # 栈顶元素不为0将被执行
                ifstack.append(stack.pop().value == 0)

            elif opcode == opcodes.OP_ELSE: # 上面俩没执行则执行这个
                if len(ifstack) == 0: return False
                ifstack.push(not ifstack.pop())

            elif opcode == opcodes.OP_ENDIF: # 终止上面仨
                if len(ifstack) == 0: return False
                ifstack.pop()

            # we are in a branch with a false condition
            if False in ifstack:
                continue

            ### Literals

            if opcode == Tokenizer.OP_LITERAL:
                stack.append(tokens.get_value(pc))

            ### Flow Control (OP_IF and kin are above)

            elif opcode == opcodes.OP_NOP:
                pass

            elif opcode == opcodes.OP_VERIFY:
                if len(stack) < 1: return False
                if bool(stack[-1]):
                    stack.pop()
                else:
                    return False

            elif opcode == opcodes.OP_RETURN:
                return False

            ### Stack Operations

            elif opcode == opcodes.OP_TOALTSTACK:
                if len(stack) < 1: return False
                altstack.append(stack.pop())

            elif opcode == opcodes.OP_FROMALTSTACK:
                if len(altstack) < 1: return False
                stack.append(altstack.pop())

            elif opcode == opcodes.OP_IFDUP:
                if len(stack) < 1: return False
                if bool(stack[-1]):
                    stack.append(stack[-1])

            elif opcode == opcodes.OP_DEPTH:
                stack.append(ByteVector.from_value(len(stack)))

            elif opcode == opcodes.OP_DROP:
                if not _stack_op(stack, lambda x: []):
                    return False

            elif opcode == opcodes.OP_DUP: # 复制操作
                if not _stack_op(stack, lambda x: [x, x]):
                    return False

            elif opcode == opcodes.OP_NIP:
                if not _stack_op(stack, lambda x1, x2: [x2]):
                    return False

            elif opcode == opcodes.OP_OVER:
                if not _stack_op(stack, lambda x1, x2: [x1, x2, x1]):
                    return False

            elif opcode == opcodes.OP_PICK:
                if len(stack) < 2: return False
                n = stack.pop().value + 1
                if not (0 <= n <= len(stack)): return False
                stack.append(stack[-n])

            elif opcode == opcodes.OP_ROLL:
                if len(stack) < 2: return False
                n = stack.pop().value + 1
                if not (0 <= n <= len(stack)): return False
                stack.append(stack.pop(-n))

            elif opcode == opcodes.OP_ROT:
                if not _stack_op(stack, lambda x1, x2, x3: [x2, x3, x1]):
                    return False

            elif opcode == opcodes.OP_SWAP:
                if not _stack_op(stack, lambda x1, x2: [x2, x1]):
                    return False

            elif opcode == opcodes.OP_TUCK:
                if not _stack_op(stack, lambda x1, x2: [x2, x1, x2]):
                    return False

            elif opcode == opcodes.OP_2DROP:
                if not _stack_op(stack, lambda x1, x2: []):
                    return False

            elif opcode == opcodes.OP_2DUP:
                if not _stack_op(stack, lambda x1, x2: [x1, x2, x1, x2]):
                    return False

            elif opcode == opcodes.OP_3DUP:
                if not _stack_op(stack, lambda x1, x2, x3: [x1, x2, x3, x1, x2, x3]):
                    return False

            elif opcode == opcodes.OP_2OVER:
                if not _stack_op(stack, lambda x1, x2, x3, x4: [x1, x2, x3, x4, x1, x2]):
                    return False

            elif opcode == opcodes.OP_2ROT:
                if not _stack_op(stack, lambda x1, x2, x3, x4, x5, x6: [x3, x4, x5, x6, x1, x2]):
                    return False

            elif opcode == opcodes.OP_2SWAP:
                if not _stack_op(stack, lambda x1, x2, x3, x4: [x3, x4, x1, x2]):
                    return False

            ### Splice Operations

            elif opcode == opcodes.OP_SIZE:
                if len(stack) < 1: return False
                stack.append(ByteVector.from_value(len(stack[-1])))

            ### Bitwise Logic Operations

            elif opcode == opcodes.OP_EQUAL:# 检查是否相等
                if not _math_op(stack, lambda x1, x2: bool(x1 == x2), False):
                    return False

            ### Arithmetic Operations

            elif opcode == opcodes.OP_1ADD:
                if not _math_op(stack, lambda a: a + One):
                    return False

            elif opcode == opcodes.OP_1SUB:
                if not _math_op(stack, lambda a: a - One):
                    return False

            elif opcode == opcodes.OP_NEGATE:
                if not _math_op(stack, lambda a: -a):
                    return False

            elif opcode == opcodes.OP_ABS:
                if not _math_op(stack, lambda a: abs(a)):
                    return False

            elif opcode == opcodes.OP_NOT:
                if not _math_op(stack, lambda a: bool(a == 0)):
                    return False

            elif opcode == opcodes.OP_0NOTEQUAL:
                if not _math_op(stack, lambda a: bool(a != 0)):
                    return False

            elif opcode == opcodes.OP_ADD:
                if not _math_op(stack, lambda a, b: a + b):
                    return False

            elif opcode == opcodes.OP_SUB:
                if not _math_op(stack, lambda a, b: a - b):
                    return False

            elif opcode == opcodes.OP_BOOLAND:
                if not _math_op(stack, lambda a, b: bool(a and b)):
                    return False

            elif opcode == opcodes.OP_BOOLOR:
                if not _math_op(stack, lambda a, b: bool(a or b)):
                    return False

            elif opcode == opcodes.OP_NUMEQUAL:
                if not _math_op(stack, lambda a, b: bool(a == b)):
                    return False

            elif opcode == opcodes.OP_NUMNOTEQUAL:
                if not _math_op(stack, lambda a, b: bool(a != b)):
                    return False

            elif opcode == opcodes.OP_LESSTHAN:
                if not _math_op(stack, lambda a, b: bool(a < b)):
                    return False

            elif opcode == opcodes.OP_GREATERTHAN:
                if not _math_op(stack, lambda a, b: bool(a > b)):
                    return False

            elif opcode == opcodes.OP_LESSTHANOREQUAL:
                if not _math_op(stack, lambda a, b: bool(a <= b)):
                    return False

            elif opcode == opcodes.OP_GREATERTHANOREQUAL:
                if not _math_op(stack, lambda a, b: bool(a >= b)):
                    return False

            elif opcode == opcodes.OP_MIN:
                if not _math_op(stack, lambda a, b: min(a, b)):
                    return False

            elif opcode == opcodes.OP_MAX:
                if not _math_op(stack, lambda a, b: max(a, b)):
                    return False

            elif opcode == opcodes.OP_WITHIN:
                if not _math_op(stack, lambda x, omin, omax: bool(omin <= x < omax)):
                    return False

            ### Crypto Operations

            elif opcode == opcodes.OP_RIPEMD160:
                if not _hash_op(stack, util.ripemd160):
                    return False

            elif opcode == opcodes.OP_SHA1:
                if not _hash_op(stack, util.sha1):
                    return False

            elif opcode == opcodes.OP_SHA256:
                if not _hash_op(stack, util.sha256):
                    return False

            elif opcode == opcodes.OP_HASH160: # 对栈顶进行hash160操作
                if not _hash_op(stack, util.hash160):
                    return False

            elif opcode == opcodes.OP_HASH256: # 对栈顶进行hash256操作
                if not _hash_op(stack, util.sha256d):
                    return False

            elif opcode == opcodes.OP_CODESEPARATOR:
                if pc > last_codeseparator:
                    last_codeseparator = pc

            # see: https://en.bitcoin.it/wiki/OP_CHECKSIG
            # 检查普通签名方式的签名并进行一定的移除操作
            elif opcode == opcodes.OP_CHECKSIG:
                # 栈内必须剩余两个以上的值（包括签名和公钥）
                if len(stack) < 2: return False

                # remove the signature and code separators for subscript
                def filter(opcode, bytes, value):
                    if opcode == opcodes.OP_CODESEPARATOR:
                        return False
                    if opcode == Tokenizer.OP_LITERAL and isinstance(value, str) and value == signature:
                        return False
                    return True

                subscript = tokens.get_subscript(last_codeseparator, filter)

                # 栈验证结束，剩余的部分为公钥与签名，check_signature验证了签名的正确性
                # 栈内部存放的tokenizer值，其自身的私有属性vector
                public_key = stack.pop().vector
                signature = stack.pop().vector

                # 这里用到检查签名的方法，这里的签名是最后剩下的，公钥也是检查过程剩下的
                valid = check_signature(signature, public_key, hash_type, subscript, transaction, input_index)

                if valid:
                    # 这一步验证成功就会在栈内剩下一个成功标记，以便最后一步校验
                    stack.append(One)
                else:
                    # print "PK", public_key.encode('hex')
                    # print "S", signature.encode('hex'), input_index
                    stack.append(Zero)

            # 这个剩余标记的意思是验证多签过程
            # 但是我们在模板中并未添加这一部分内容，因此是不被识别的。
            elif opcode == opcodes.OP_CHECKMULTISIG:
                if len(stack) < 2: return False

                # get all the public keys
                count = stack.pop().value
                if len(stack) < count: return False
                public_keys = [stack.pop() for i in range(count)]

                if len(stack) < 1: return False

                # get all the signautres
                count = stack.pop().value
                if len(stack) < count: return False
                signatures = [stack.pop() for i in range(count)]

                # due to a bug in the original client, discard an extra operand
                if len(stack) < 1: return False
                stack.pop()

                # remove the signature and code separators for subscript
                def filter(opcode, bytes, value):
                    if opcode == opcodes.OP_CODESEPARATOR:
                        return False
                    if opcode == Tokenizer.OP_LITERAL and isinstance(value, str) and value in signatures:
                        return False
                    return True

                subscript = tokens.get_subscript(last_codeseparator, filter)

                matched = dict()
                for signature in signatures:

                    # do any remaining public keys work?
                    for public_key in public_keys:
                        if check_signature(signature, public_key, hash_type, subscript, transaction, input_index):
                            break
                    else:
                        public_key is None

                    # record which public key and remove from future canidate
                    if public_key is not None:
                        matched[signature] = public_key
                        public_keys.remove(public_key)

                # did each signature have a matching public key?
                if len(matched) == len(signatures):
                    stack.append(One)
                else:
                    # print "MULTISIG"
                    # print "PK", public_key.encode('hex')
                    # print "S", signature.encode('hex'), input_index
                    stack.append(Zero)

            elif opcode == opcodes.OP_RESERVED:
                return False

            elif opcode == opcodes.OP_VER:
                return False

            elif opcode == opcodes.OP_RESERVED1:
                return False

            elif opcode == opcodes.OP_RESERVED2:
                return False

            elif opcodes.OP_NOP1 <= opcode <= opcodes.OP_NOP10:
                pass

            else:
                # print "UNKNOWN OPCODE: %d" % opcode
                return False

        # print "STACK:"
        # print "  " + "\n  ".join(str(i) for i in stack)

        # 检查最后剩下的是否为True
        if len(stack) and bool(stack[-1]):
            return True

        return False
