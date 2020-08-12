#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Arquivo pertencente ao treinamento de Desenvolvimento de Exploit
# Autor: Hélvio Junior (M4v3r1ck)
#
# Proibida a reprodução ou publicação deste material sem prévia autorização expressa
#
#Filename: encoder.py

import socket, time, sys, os
from struct import *


class Configuration(object):
    ''' Stores configuration variables and functions for Encoder. '''
    version = '0.0.9'

    payload_file = ''
    out_file = ''
    verbose =False
    cmd_line = ''

    @staticmethod
    def load_from_arguments():
        ''' Sets configuration values based on Argument.args object '''
        import getopt, argparse

        parser = argparse.ArgumentParser()

        requiredNamed = parser.add_argument_group('SETTINGS')

        requiredNamed.add_argument('-p',
            action='store',
            dest='payload_file',
            metavar='Payload_File',
            type=str,
            default='',
            required=True,
            help='Binary peylod data')

        customNamed = parser.add_argument_group('CUSTOM')

        customNamed.add_argument('-o',
            action='store',
            dest='out_file',
            metavar='output_file',
            default='decoder.asm',
            type=str,
            help=Color.s('save output to disk (default: {G}decoder.asm{W})'))

        args = parser.parse_args()

        for a in sys.argv:
            Configuration.cmd_line += "%s " % a

        Configuration.payload_file = args.payload_file
        Configuration.out_file = args.out_file

        Color.pl('{+} {W}Startup parameters')


        if not os.path.isfile(Configuration.payload_file):
            Color.pl('{!} {R}error: payload file not found {O}%s{R}{W}\r\n' % Configuration.payload_file)
            sys.exit(0)

        try:
            with open(Configuration.payload_file, 'r') as f:
                # file opened for writing. write to it here
                pass
        except IOError as x:
            if x.errno == errno.EACCES:
                Color.pl('{!} {R}error: could not open payload file {O}permission denied{R}{W}\r\n')
                sys.exit(0)
            elif x.errno == errno.EISDIR:
                Color.pl('{!} {R}error: could not open payload file {O}it is an directory{R}{W}\r\n')
                sys.exit(0)
            else:
                Color.pl('{!} {R}error: could not open payload file {W}\r\n')
                sys.exit(0)

        Color.pl('     {C}Payload file:{O} %s{W}' % Configuration.payload_file)
        Color.pl('     {C}Output file:{O} %s{W}' % Configuration.out_file)


class Color(object):
    ''' Helper object for easily printing colored text to the terminal. '''

    # Basic console colors
    colors = {
        'W' : '\033[0m',  # white (normal)
        'R' : '\033[31m', # red
        'G' : '\033[32m', # green
        'O' : '\033[33m', # orange
        'B' : '\033[34m', # blue
        'P' : '\033[35m', # purple
        'C' : '\033[36m', # cyan
        'GR': '\033[37m', # gray
        'D' : '\033[2m'   # dims current color. {W} resets.
    }

    # Helper string replacements
    replacements = {
        '{+}': ' {W}{D}[{W}{G}+{W}{D}]{W}',
        '{!}': ' {O}[{R}!{O}]{W}',
        '{?}': ' {W}[{C}?{W}]',
        '{*}': ' {W}[{B}*{W}]'
    }

    last_sameline_length = 0

    @staticmethod
    def p(text):
        '''
        Prints text using colored format on same line.
        Example:
            Color.p("{R}This text is red. {W} This text is white")
        '''
        sys.stdout.write(Color.s(text))
        sys.stdout.flush()
        if '\r' in text:
            text = text[text.rfind('\r')+1:]
            Color.last_sameline_length = len(text)
        else:
            Color.last_sameline_length += len(text)

    @staticmethod
    def pl(text):
        '''Prints text using colored format with trailing new line.'''
        Color.p('%s\n' % text)
        Color.last_sameline_length = 0

    @staticmethod
    def pe(text):
        '''Prints text using colored format with leading and trailing new line to STDERR.'''
        sys.stderr.write(Color.s('%s\n' % text))
        Color.last_sameline_length = 0

    @staticmethod
    def s(text):
        ''' Returns colored string '''
        output = text
        for (key,value) in Color.replacements.items():
            output = output.replace(key, value)
        for (key,value) in Color.colors.items():
            output = output.replace("{%s}" % key, value)
        return output

    @staticmethod
    def sc(text):
        ''' Returns non colored string '''
        output = text
        for (key,value) in Color.replacements.items():
            output = output.replace(key, value)
        for (key,value) in Color.colors.items():
            output = output.replace("{%s}" % key, '')
        return output

    @staticmethod
    def clear_line():
        spaces = ' ' * Color.last_sameline_length
        sys.stdout.write('\r%s\r' % spaces)
        sys.stdout.flush()
        Color.last_sameline_length = 0

    @staticmethod
    def clear_entire_line():
        import os
        (rows, columns) = os.popen('stty size', 'r').read().split()
        Color.p("\r" + (" " * int(columns)) + "\r")



class Encoder(object):

    def __init__(self):

        asm  = "; File generated by Printable ASCII encoder\n"

        with open(Configuration.out_file, "w") as f:
            f.write(asm + "\n")

    def write_file(self, text):
        with open(Configuration.out_file, "a") as f:
            f.write(text + "\n")


    def to_hex_string(self, value):
        res = ""
        for b in value:
            res += "\\x%02x" % ord(b)
        return res

    def print_instruction(self, operation, value):
        res = ""
        if "\x68" == operation: #PUSH 
            res += "PUSH 0x"
        elif "\x25" == operation: #AND EAX
            res += "AND EAX, 0x"
        elif "\x35" == operation: #XOR EAX
            res += "XOR EAX, 0x"
        elif "\x2d" == operation: #SUB EAX
            res += "SUB EAX, 0x"

        for b in value:
            res += "%02x" % ord(b)

        self.write_file(res)


    def print_set_eax(self):
        self.write_file("; Setting EAX = 0xffffffff")
        self.write_file("push 0x41414141")
        self.write_file("pop eax")
        self.write_file("xor eax,0x41414141")
        self.write_file("dec eax")
        self.write_file("push eax")
        self.write_file("pop ebx")


    def print_restore_eax(self):
        self.write_file("; restoring EAX = 0xffffffff from ebx")
        self.write_file("push ebx")
        self.write_file("pop eax")


    def calc_op2(self, n1,n2,op):
        if op == "\x2d":
            return (0xff - n1 - n2)
        elif op == "\x25":
            return ((0xff & n1) & n2)
        elif op == "\x35":
            return ((0xff ^ n1) ^ n2)


    def calc_op3(self, n1,n2,n3,op):
        if op == "\x2d":
            return (0xff - n1 - n2 - n3)
        elif op == "\x25":
            return (((0xff & n1) & n2) & n3)
        elif op == "\x35":
            return (((0xff ^ n1) ^ n2) ^ n3)

    def payload_encoder(self, badchars, payload):
        
        # Verifica simetria em 4 bytes
        p1 = payload
        if len(p1) % 4 != 0:
            p1 += "\x90" * (4 - (len(p1) % 4))

        p=len(p1)-1
        l=len(p1)
        ret_opcode=""
        operation=""
        operation_desc = ""
        ops = []
        opi = 0
        
        offset = 0
        Color.pl('{+} {W}Payload size: {O}%d{W} bytes' % l)
        Color.pl('{*} {W}Decoded: {C}%s{W}' % (self.to_hex_string(p1)))

        if "\x25" not in badchars: #AND EAX
            ops.append("\x25")
        if "\x35" not in badchars: #XOR EAX
            ops.append("\x35")
        if "\x2d" not in badchars: #SUB EAX
            ops.append("\x2d")

        self.print_set_eax()

        # Executa de modo reverso (de traz p/ frente)
        while p >= 0:
        
            offset += 4

            done=False
            ret_opcode=""
        
            c4 = p1[p:p+1]
            p -= 1
            c3 = p1[p:p+1]
            p -= 1
            c2 = p1[p:p+1]
            p -= 1
            c1 = p1[p:p+1]
            p -= 1

            if c4 == "":
                break;

            if c1 == "":
                c1 = "\x90"

            if c2 == "":
                c2 = "\x90"

            if c3 == "":
                c3 = "\x90"

            Color.pl('{*} {W}Encoding [%d/%d]: {O}0x%02x%02x%02x%02x{W}' % (offset, l, ord(c1), ord(c2), ord(c3), ord(c4)))
            self.write_file(";\n;Encoding: 0x%02x%02x%02x%02x" % (ord(c1), ord(c2), ord(c3), ord(c4)))

            if c4 not in badchars and c3 not in badchars and c2 not in badchars and c1 not in badchars:
                # os 4 não estão na lista só faz o push
                ret_opcode = c4 
                ret_opcode += c3 
                ret_opcode += c2 
                ret_opcode += c1 
                self.print_instruction("\x68", ret_opcode)
                done=True
            else:
                done = False
                for operation in ops:
                
                    if done:
                        break;

                    # 2 operacoes
                    op1 = ["","","",""]
                    op2 = ["","","",""]
                    for n1 in reversed(range(1,255)):
                        if chr(n1) not in badchars:
                            for n2 in reversed(range(1,255)):
                                if chr(n2) not in badchars:
                                    if self.calc_op2(n1,n2,operation) == ord(c1) and op1[0] == "":
                                        op1[0] = chr(n1)
                                        op2[0] = chr(n2)
                                    if self.calc_op2(n1,n2,operation) == ord(c2) and op1[1] == "":
                                        op1[1] = chr(n1)
                                        op2[1] = chr(n2)
                                    if self.calc_op2(n1,n2,operation) == ord(c3) and op1[2] == "":
                                        op1[2] = chr(n1)
                                        op2[2] = chr(n2)
                                    if self.calc_op2(n1,n2,operation) == ord(c4) and op1[3] == "":
                                        op1[3] = chr(n1)
                                        op2[3] = chr(n2)

                    if op1[0] != "" and op1[1] != "" and op1[2] != "" and op1[3] != "":
                        self.print_restore_eax()
                        self.write_file("; calc")
                        ret_opcode = op1[3]
                        ret_opcode += op1[2]
                        ret_opcode += op1[1]
                        ret_opcode += op1[0]

                        self.print_instruction(operation, ret_opcode)

                        ret_opcode = op2[3]
                        ret_opcode += op2[2]
                        ret_opcode += op2[1]
                        ret_opcode += op2[0]
                        self.print_instruction(operation, ret_opcode)
                        self.write_file("PUSH EAX")
                        done=True


                # 3 interações
                if not done:
                    done = False
                    for operation in ops:
                    
                    
                        if "\x25" == operation: #AND EAX
                            operation_desc = "AND EAX"
                        elif "\x35" == operation: #XOR EAX
                            operation_desc = "XOR EAX"
                        elif "\x2d" == operation: #SUB EAX
                            operation_desc = "SUB EAX"
                    
                        if done:
                            break;

                        op1 = ["","","",""]
                        op2 = ["","","",""]
                        op3 = ["","","",""]
                        for n1 in reversed(range(1,255)):
                            if chr(n1) not in badchars:
                                for n2 in reversed(range(1,255)):
                                    if chr(n2) not in badchars:
                                        for n3 in reversed(range(1,255)):
                                            if chr(n3) not in badchars:
                                                if self.calc_op3(n1,n2,n3,operation) == ord(c1) and op1[0] == "":
                                                    op1[0] = chr(n1)
                                                    op2[0] = chr(n2)
                                                    op3[0] = chr(n3)
                                                if self.calc_op3(n1,n2,n3,operation) == ord(c2) and op1[1] == "":
                                                    op1[1] = chr(n1)
                                                    op2[1] = chr(n2)
                                                    op3[1] = chr(n3)
                                                if self.calc_op3(n1,n2,n3,operation) == ord(c3) and op1[2] == "":
                                                    op1[2] = chr(n1)
                                                    op2[2] = chr(n2)
                                                    op3[2] = chr(n3)
                                                if self.calc_op3(n1,n2,n3,operation) == ord(c4) and op1[3] == "":
                                                    op1[3] = chr(n1)
                                                    op2[3] = chr(n2)
                                                    op3[3] = chr(n3)

                        if op1[0] != "" and op1[1] != "" and op1[2] != "" and op1[3] != "":
                            self.print_restore_eax()
                            self.write_file("; calc")

                            ret_opcode = op1[3]
                            ret_opcode += op1[2]
                            ret_opcode += op1[1]
                            ret_opcode += op1[0]

                            self.print_instruction(operation, ret_opcode)

                            ret_opcode = op2[3]
                            ret_opcode += op2[2]
                            ret_opcode += op2[1]
                            ret_opcode += op2[0]
                            self.print_instruction(operation, ret_opcode)

                            ret_opcode = op3[3]
                            ret_opcode += op3[2]
                            ret_opcode += op3[1]
                            ret_opcode += op3[0]
                            self.print_instruction(operation, ret_opcode)
                            self.write_file("PUSH EAX")
                            done=True


                if not done:
                    # Modo hard, um por um dos bytes
                    txt1 = self.calc_hard(operation, ord(c1), badchars)
                    txt2 = self.calc_hard(operation, ord(c2), badchars)
                    txt3 = self.calc_hard(operation, ord(c3), badchars)
                    txt4 = self.calc_hard(operation, ord(c4), badchars)
                    if txt1 and txt2 and txt3 and txt4:
                        self.print_restore_eax()
                        self.write_file(txt4)
                        self.print_restore_eax()
                        self.write_file(txt3)
                        self.print_restore_eax()
                        self.write_file(txt2)
                        self.print_restore_eax()
                        self.write_file(txt1)
                        done = True

                if not done:
                    raise Exception('Encoder error') 


    def calc_hard(self, op, b1, badchars):
        found = False
        # sempre presumo que EAX = 0xffffffff
        res = ""
        if op == "\x2d": # Somente no modo subtracao
            c1 = 0xff - b1

            if b1 == 0: # valor desejado é Zero
                res += "inc eax\n"
                res += "push ax\n"
                res += "inc esp\n"

            elif b1 == 0xff: # Valor desejado é 0xff

                res += "push ax\n"
                res += "inc esp\n"

            else:

                # qual o mais proximo do resto posso chegar
                resto = c1
                loop = True
                while loop:
                    loop = False
                    for n1 in reversed(range(1,255)):
                        if chr(n1) not in badchars:
                            tmp = resto - n1
                            if tmp > 0:
                                res += "sub al,0x%02x\n" % n1
                                resto -= n1
                                loop = True
                                break


                for i in range(0, resto):
                    res += "dec eax\n"

                res += "push ax\n"
                res += "push ax\n"
                res += "inc esp\n"
                res += "pop ax\n"
                res += "inc esp\n"
                res += "push ax\n"
                res += "inc esp\n"
            
            return res
        else:
            return False

def main():

    Configuration.load_from_arguments()
        
    badchars = []

    for v1 in range(0,33):
        badchars.append(chr(v1))

    for v1 in range(126,256):
        badchars.append(chr(v1))

    with open(Configuration.payload_file, "r") as f:
        bdata = f.read()

    enc = Encoder()
    enc.payload_encoder(badchars, bdata)

if __name__== "__main__":
  main()
