import sys  
from pathlib import Path
from enum import Enum,auto
from dataclasses import dataclass
import re
from typing import List , Dict
# this regex matches either:
#  - a double-quoted string:   "[^"]*"  
#  - or a run of non-comma, non-paren, non-whitespace chars: [^,\s()]+
TOKEN_RE = re.compile(r'"[^"]*"|[(),]|[^,"\s()]+')
# A simple list of all ZX16 instruction mnemonics as strings
def sign_extend_hex(hex_value: str, bits: int = 16) -> str:
   """Sign-extend a hexadecimal value to match the specified bit width."""
   value = int(hex_value, 16)
   sign_bit = 1 << (bits - 1)
   extended_value = (value & (sign_bit - 1)) - (value & sign_bit)
   return f"{extended_value & ((1 << bits) - 1):0{bits // 4}X}"
def hex_to_decimal(hex_value: str) -> int:
      try:
         return int(hex_value, 16)
      except ValueError:
         print(f"Error: Invalid hexadecimal value '{hex_value}'")
         return 0

class TokenType(Enum):
    """Token types for lexical analysis."""
    INSTRUCTION = auto()
    PINSTRUCTION = auto()
    REGISTER = auto()
    DECIMMEDIATE = auto()
    BINIMMEDIATE = auto()
    HEXIMMEDIATE = auto()
    DEFLABEL = auto()
    APPLABEL = auto()
    DIRECTIVE = auto()
    STRING = auto()
    OP=auto()
    COMMA = auto()
    LPAREN = auto()
    RPAREN = auto()

InstructionSet = [
    # R-Type
    'add', 'sub', 'slt', 'sltu', 'sll', 'srl', 'sra', 'or', 'and', 'xor', 'mv', 'jr', 'jalr',
    # I-Type
    'addi', 'slti', 'sltui', 'slli', 'srli', 'srai', 'ori', 'andi', 'xori', 'li',
    # B-Type
    'beq', 'bne', 'bz', 'bnz', 'blt', 'bge', 'bltu', 'bgeu',
    # S-Type
    'sb', 'sw',
    # L-Type
    'lb', 'lw', 'lbu',
    # J-Type
    'j', 'jal',
    # U-Type
    'lui', 'auipc',
    # SYS-Type
    'ecall',
]

pseudo_instructions = {
    # Pseudo-instructions
    'li16' : 4, 'la' : 4, 'push' : 4,
      'pop' : 4, 'call' : 2, 'ret' : 2 ,
        'inc' : 2, 'dec':2, 'neg' : 4, 'not' : 2,
          'clr':2, 'nop':2
}
directives = [
    '.text', '.data', '.bss', '.org', '.align',
    '.byte', '.word', '.string', '.ascii', '.space', '.fill',
    '.equ', '.set', '.global', '.extern',
    '.ifdef', '.ifndef', '.if', '.else', '.endif',
    '.include', '.incbin',
]
registers ={
    't0': 'x0',
     'ra': 'x1',
     'sp': 'x2',
    's0': 'x3',
     's1': 'x4',
     't1': 'x5',
     'a0': 'x6',
     'a1': 'x7'
}
    
@dataclass
class Token:
    """Represents a lexical token."""
    type: TokenType
    value: str
    size: int = 0  # Size in bytes, default to zero if not applicable
@dataclass
class Symbol:
    """Represents a symbol in the symbol table."""
    name: str
    value: int
    defined: bool = False
    global_symbol: bool = False
class ZX16Lexer:
      def __init__(self):
         self.tokens = []
      def remove_whitespace(self, source_code):
         # Remove leading and trailing whitespace from each line
         cleaned_code = []
         for line in source_code:
            cleaned_line = line.strip()  # Remove leading whitespace
            if cleaned_line:  # Ensure the line is not empty
               cleaned_code.append(cleaned_line)
         return cleaned_code
      def remove_comments(self, source_code):
         # Placeholder for comment removal logic
         cleaned_code = []
         for line in source_code:
               if not line.startswith('#'):
                  cleaned_code.append(line)
         for i, line in enumerate(cleaned_code):
             if '#' in line:
                cleaned_code[i] = line.split('#', 1)[0].strip()
                  
         return cleaned_code
      
      def tokenize(self, source_code)-> List[Token]:
          words = []
          for line in source_code:
            line = line.strip()
            if not line:
               continue
            tokens = TOKEN_RE.findall(line)
            words.extend(tokens)
          print(f"Tokenized words: {words}")
          for word in words:
               n= len(word)
               firstchar = word[0]
               # Instructions or labels or registers
               if firstchar.isalpha():
                 i=0
                 value=""
                 while i<n:
                    value += word[i]
                    i+=1
                 if value.lower() in InstructionSet:
                   self.tokens.append(Token(TokenType.INSTRUCTION, value, size =2))
                 elif value.lower() in pseudo_instructions.keys():
                     self.tokens.append(Token(TokenType.PINSTRUCTION, value, pseudo_instructions[value.lower()]))
                 elif value.endswith(':'):
                      self.tokens.append(Token(TokenType.DEFLABEL, value[:-1]))
                 elif value.lower() in registers.keys() :
                     self.tokens.append(Token(TokenType.REGISTER, registers[value.lower()]))
                 elif value.lower() in registers.values():
                     self.tokens.append(Token(TokenType.REGISTER, value.lower()))
                 else:
                     self.tokens.append(Token(TokenType.APPLABEL, value))
               # Directives
               elif firstchar== '.':
                    i=0
                    value=""
                    while i<n:
                           value += word[i]
                           i+=1
                    if value.lower() in directives:
                        self.tokens.append(Token(TokenType.DIRECTIVE, value))
                    else :
                        print(f"Unknown directive: {value}")
               # Hexadecimal or Decimal Immediate
               elif firstchar.isdigit() or firstchar == '-':
                    secondchar = word[1] if n > 1 else ''
                    value = word
                    if secondchar == 'x' or secondchar == 'X':
                        # Hexadecimal immediate
                        self.tokens.append(Token(TokenType.HEXIMMEDIATE, value))
                    elif secondchar == 'b' or secondchar == 'B':
                        # Binary immediate
                        self.tokens.append(Token(TokenType.BINIMMEDIATE, value))
                    else:
                        # Decimal immediate
                        self.tokens.append(Token(TokenType.DECIMMEDIATE, value))
               # Strings
               elif firstchar == '"' or firstchar == "'":
                    value = word.strip('"').strip("'")
                    self.tokens.append(Token(TokenType.STRING, value))
               # Operators
               elif firstchar in ['+', '-', '*', '/', '%', '=', '>', '<', '&', '|', '^', '!', '~' ,
                                  '+=', '-=', '*=', '/=', '%=', '==', '!=', '>', '<', '>=', '<=',
                                  '&&', '||', '<<', '>>', '++', '--']:
                    self.tokens.append(Token(TokenType.OP, word))
               elif firstchar == ',':
                    self.tokens.append(Token(TokenType.COMMA, word))
               elif firstchar == '(':
                     self.tokens.append(Token(TokenType.LPAREN, word))
               elif firstchar == ')':
                     self.tokens.append(Token(TokenType.RPAREN, word))
               else:
                    print(f"Unknown token: {word}")
          print("Tokens:")
          for token in self.tokens:
              print(f"  Type: {token.type.name}, Value: {token.value}")
          return self.tokens
    
class ZX16Assembler:
   def __init__(self):
        self.tokens: List[Token] = []
        self.symbols : List[Symbol] = []
        self.current_address = 0x0000  # Starting address for the program
        self.section_addresses: Dict[str, int] = {
            ".text": 0x0020,
            ".data": 0x8000,
            ".bss": 0x9000
        }

   def assemble(self,source_code):
      lexer = ZX16Lexer()
      source_code = lexer.remove_whitespace(source_code)
      source_code = lexer.remove_comments(source_code)
      # print(f"Processed source code from {file_path}:\n{source_code}")
      self.tokens= lexer.tokenize(source_code)
      # print (f"Source code from {file_path}:\n{source_code}") 
      self.pass1(); 
   def pass1(self):
      for index, token in enumerate(self.tokens):
           if token.type == TokenType.DIRECTIVE:
               if token.value == '.text':
                   self.current_address = self.section_addresses['.text']
               elif token.value == '.data':
                   self.current_address = self.section_addresses['.data']
               elif token.value == '.bss':
                   self.current_address = self.section_addresses['.bss']
               elif token.value.startswith('.org'):
                   # Handle .org directive
                   if index + 1 < len(self.tokens) and self.tokens[index + 1].type == TokenType.HEXIMMEDIATE:
                       self.current_address = hex_to_decimal(self.tokens[index + 1].value)
                   elif index + 1 < len(self.tokens) and self.tokens[index + 1].type == TokenType.DECIMMEDIATE:
                    self.current_address = int(self.tokens[index + 1].value)
               elif token.value.startswith('.align'):
                   ## TODO
                   pass
           if token.type == TokenType.DEFLABEL:
               label_name = token.value
               if any(symbol.name == label_name for symbol in self.symbols):
                   print(f"Error: Label '{label_name}' is already defined.")
               else:
                   self.symbols.append(Symbol(name=label_name, value=self.current_address, defined=True))
           self.current_address += token.size 
      print("Symbols Table:")
      for symbol in self.symbols:
          print(f"  Name: {symbol.name}, Value: {symbol.value}, Defined: {symbol.defined}, Global: {symbol.global_symbol}")
           
   def pass2(self):
         pass
   

def main():
   file_path = Path(__file__).parent / "ex-1.s"
   try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
            source_code = source_code.splitlines()
   except Exception as e:
        print(f"Error: Unable to open file. {e}")
        sys.exit(1)
   assembler = ZX16Assembler()
   assembler.assemble(source_code)
   print("Assembly completed successfully.")
  
  
    


if __name__ == "__main__":
    sys.exit(main())