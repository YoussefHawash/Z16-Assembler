import sys  
from pathlib import Path
from enum import Enum, auto
from dataclasses import dataclass
import re
from typing import List, Dict, Tuple, Optional, Union
import struct

# Token regex - matches quoted strings, operators, or identifiers
TOKEN_RE = re.compile(r'"[^"]*"|[(),]|[^,"\s()]+')

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

def sign_extend(value: int, bits: int) -> int:
    """Sign extend a value from 'bits' to 16 bits"""
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

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
    OP = auto()
    COMMA = auto()
    LPAREN = auto()
    RPAREN = auto()

# Base instruction set (all lowercase for case-insensitive matching)
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

# Pseudo-instructions with their expansion size in bytes
pseudo_instructions = {
    'li16': 4, 'la': 4, 'push': 4, 'pop': 4, 'call': 2, 'ret': 2,
    'inc': 2, 'dec': 2, 'neg': 4, 'not': 2, 'clr': 2, 'nop': 2
}

directives = [
    '.text', '.data', '.bss', '.org', '.align',
    '.byte', '.word', '.string', '.ascii', '.space', '.fill',
    '.equ', '.set', '.global', '.extern',
    '.ifdef', '.ifndef', '.if', '.else', '.endif',
    '.include', '.incbin',
]

# Register mapping - both numeric and ABI names
registers = {
    't0': 'x0', 'ra': 'x1', 'sp': 'x2', 's0': 'x3',
    's1': 'x4', 't1': 'x5', 'a0': 'x6', 'a1': 'x7',
    'x0': 'x0', 'x1': 'x1', 'x2': 'x2', 'x3': 'x3',
    'x4': 'x4', 'x5': 'x5', 'x6': 'x6', 'x7': 'x7'
}

@dataclass
class Token:
    """Represents a lexical token."""
    type: TokenType
    value: str
    size: int = 0  # Size in bytes
    line: int = 0  # Line number for error reporting

@dataclass
class Symbol:
    """Represents a symbol in the symbol table."""
    name: str
    value: int
    defined: bool = False
    global_symbol: bool = False
    section: str = '.text'

@dataclass
class Instruction:
    """Represents an assembled instruction."""
    address: int
    opcode: int
    size: int = 2
    source_line: int = 0
    mnemonic: str = ""

class ZX16Lexer:
    def __init__(self):
        self.tokens = []
        self.line_number = 0

    def remove_whitespace(self, source_code):
        """Remove leading and trailing whitespace from each line"""
        cleaned_code = []
        for line in source_code:
            cleaned_line = line.strip()
            if cleaned_line:
                cleaned_code.append(cleaned_line)
        return cleaned_code

    def remove_comments(self, source_code):
        """Remove comments from source code"""
        cleaned_code = []
        for line in source_code:
            if not line.startswith('#'):
                cleaned_code.append(line)
        
        for i, line in enumerate(cleaned_code):
            if '#' in line:
                cleaned_code[i] = line.split('#', 1)[0].strip()
        
        return cleaned_code

    def tokenize(self, source_code) -> List[Token]:
        """Tokenize the source code into tokens"""
        self.tokens = []
        
        for line_num, line in enumerate(source_code, 1):
            line = line.strip()
            if not line:
                continue
            
            tokens = TOKEN_RE.findall(line)
            
            for word in tokens:
                token = self._create_token(word, line_num)
                if token:
                    self.tokens.append(token)
        
        print("Tokens:")
        for token in self.tokens:
            print(f"  Type: {token.type.name}, Value: {token.value}")
        
        return self.tokens

    def _create_token(self, word: str, line_num: int) -> Optional[Token]:
        """Create a token from a word"""
        n = len(word)
        if n == 0:
            return None
            
        firstchar = word[0]
        
        # Instructions, labels, or registers (alphabetic start)
        if firstchar.isalpha():
            value = word.lower()
            
            if value in InstructionSet:
                return Token(TokenType.INSTRUCTION, value, size=2, line=line_num)
            elif value in pseudo_instructions:
                return Token(TokenType.PINSTRUCTION, value, pseudo_instructions[value], line=line_num)
            elif word.endswith(':'):
                return Token(TokenType.DEFLABEL, word[:-1], line=line_num)
            elif value in registers:
                return Token(TokenType.REGISTER, registers[value], line=line_num)
            else:
                return Token(TokenType.APPLABEL, word, line=line_num)
        
        # Directives (start with .)
        elif firstchar == '.':
            if word.lower() in directives:
                return Token(TokenType.DIRECTIVE, word.lower(), line=line_num)
            else:
                print(f"Line {line_num}: Unknown directive: {word}")
                return None
        
        # Numbers and immediates
        elif firstchar.isdigit() or firstchar == '-':
            secondchar = word[1] if n > 1 else ''
            
            if secondchar in ['x', 'X']:
                return Token(TokenType.HEXIMMEDIATE, word, line=line_num)
            elif secondchar in ['b', 'B']:
                return Token(TokenType.BINIMMEDIATE, word, line=line_num)
            else:
                return Token(TokenType.DECIMMEDIATE, word, line=line_num)
        
        # Strings
        elif firstchar in ['"', "'"]:
            value = word.strip('"').strip("'")
            return Token(TokenType.STRING, value, line=line_num)
        
        # Single character tokens
        elif firstchar == ',':
            return Token(TokenType.COMMA, word, line=line_num)
        elif firstchar == '(':
            return Token(TokenType.LPAREN, word, line=line_num)
        elif firstchar == ')':
            return Token(TokenType.RPAREN, word, line=line_num)
        
        # Operators
        else:
            return Token(TokenType.OP, word, line=line_num)

class ZX16Assembler:
    def __init__(self):
        self.tokens: List[Token] = []
        self.symbols: Dict[str, Symbol] = {}
        self.instructions: List[Instruction] = []
        self.data_bytes: List[int] = []
        self.current_address = 0x0000
        self.current_section = '.text'
        self.section_addresses = {
            ".text": 0x0020,
            ".data": 0x8000,
            ".bss": 0x9000
        }
        self.memory = bytearray(65536)  # 64KB memory
        
        # Instruction encoding tables
        self._init_instruction_tables()

    def _init_instruction_tables(self):
        """Initialize instruction encoding tables"""
        # R-Type instructions (opcode = 000)
        self.r_type_encodings = {
            'add': {'funct4': 0x0, 'func3': 0x0},
            'sub': {'funct4': 0x1, 'func3': 0x0},
            'slt': {'funct4': 0x2, 'func3': 0x1},
            'sltu': {'funct4': 0x3, 'func3': 0x2},
            'sll': {'funct4': 0x4, 'func3': 0x3},
            'srl': {'funct4': 0x5, 'func3': 0x3},
            'sra': {'funct4': 0x6, 'func3': 0x3},
            'or': {'funct4': 0x7, 'func3': 0x4},
            'and': {'funct4': 0x8, 'func3': 0x5},
            'xor': {'funct4': 0x9, 'func3': 0x6},
            'mv': {'funct4': 0xA, 'func3': 0x7},
            'jr': {'funct4': 0xB, 'func3': 0x0},
            'jalr': {'funct4': 0xC, 'func3': 0x0}
        }
        
        # I-Type instructions (opcode = 001)
        self.i_type_encodings = {
            'addi': {'func3': 0x0},
            'slti': {'func3': 0x1},
            'sltui': {'func3': 0x2},
            'slli': {'func3': 0x3, 'shift_type': 0x1},
            'srli': {'func3': 0x3, 'shift_type': 0x2},
            'srai': {'func3': 0x3, 'shift_type': 0x4},
            'ori': {'func3': 0x4},
            'andi': {'func3': 0x5},
            'xori': {'func3': 0x6},
            'li': {'func3': 0x7}
        }
        
        # B-Type instructions (opcode = 010)
        self.b_type_encodings = {
            'beq': {'func3': 0x0},
            'bne': {'func3': 0x1},
            'bz': {'func3': 0x2},
            'bnz': {'func3': 0x3},
            'blt': {'func3': 0x4},
            'bge': {'func3': 0x5},
            'bltu': {'func3': 0x6},
            'bgeu': {'func3': 0x7}
        }
        
        # S-Type instructions (opcode = 011)
        self.s_type_encodings = {
            'sb': {'func3': 0x0},
            'sw': {'func3': 0x1}
        }
        
        # L-Type instructions (opcode = 100)
        self.l_type_encodings = {
            'lb': {'func3': 0x0},
            'lw': {'func3': 0x1},
            'lbu': {'func3': 0x4}
        }

    def assemble(self, source_code):
        """Main assembly function"""
        lexer = ZX16Lexer()
        source_code = lexer.remove_whitespace(source_code)
        source_code = lexer.remove_comments(source_code)
        self.tokens = lexer.tokenize(source_code)
        
        print("\n=== Pass 1: Building symbol table ===")
        self.pass1()
        
        print("\n=== Pass 2: Generating code ===")
        self.pass2()
        
        return self.memory

    def pass1(self):
        """First pass: collect symbols and calculate addresses"""
        i = 0
        while i < len(self.tokens):
            token = self.tokens[i]
            
            if token.type == TokenType.DIRECTIVE:
                i = self._handle_directive_pass1(i)
            elif token.type == TokenType.DEFLABEL:
                self._define_label(token.value, self.current_address)
                i += 1
            elif token.type in [TokenType.INSTRUCTION, TokenType.PINSTRUCTION]:
                self.current_address += token.size
                i += 1
            else:
                i += 1
        
        print("Symbol Table:")
        for name, symbol in self.symbols.items():
            print(f"  {name}: 0x{symbol.value:04X} ({symbol.section})")

    def pass2(self):
        """Second pass: generate machine code"""
        self.current_address = self.section_addresses['.text']
        self.current_section = '.text'
        
        i = 0
        while i < len(self.tokens):
            token = self.tokens[i]
            
            if token.type == TokenType.DIRECTIVE:
                i = self._handle_directive_pass2(i)
            elif token.type == TokenType.DEFLABEL:
                i += 1
            elif token.type == TokenType.INSTRUCTION:
                i = self._encode_instruction(i)
            elif token.type == TokenType.PINSTRUCTION:
                i = self._expand_pseudo_instruction(i)
            else:
                i += 1

    def _handle_directive_pass1(self, index: int) -> int:
        """Handle directives in pass 1"""
        token = self.tokens[index]
        
        if token.value == '.text':
            self.current_address = self.section_addresses['.text']
            self.current_section = '.text'
            return index + 1
        elif token.value == '.data':
            self.current_address = self.section_addresses['.data']
            self.current_section = '.data'
            return index + 1
        elif token.value == '.bss':
            self.current_address = self.section_addresses['.bss']
            self.current_section = '.bss'
            return index + 1
        elif token.value == '.org':
            if index + 1 < len(self.tokens):
                next_token = self.tokens[index + 1]
                if next_token.type == TokenType.HEXIMMEDIATE:
                    self.current_address = hex_to_decimal(next_token.value)
                elif next_token.type == TokenType.DECIMMEDIATE:
                    self.current_address = int(next_token.value)
                return index + 2
            return index + 1
        elif token.value in ['.byte', '.word', '.string', '.ascii']:
            # Calculate size for data directives
            size = self._calculate_data_size(index)
            self.current_address += size
            # Skip past the data values
            i = index + 1
            while i < len(self.tokens) and self.tokens[i].type != TokenType.DIRECTIVE:
                i += 1
            return i
        elif token.value == '.space':
            if index + 1 < len(self.tokens):
                next_token = self.tokens[index + 1]
                if next_token.type == TokenType.DECIMMEDIATE:
                    self.current_address += int(next_token.value)
                return index + 2
            return index + 1
        
        return index + 1

    def _handle_directive_pass2(self, index: int) -> int:
        """Handle directives in pass 2"""
        token = self.tokens[index]
        
        if token.value == '.text':
            self.current_address = self.section_addresses['.text']
            self.current_section = '.text'
            return index + 1
        elif token.value == '.data':
            self.current_address = self.section_addresses['.data']
            self.current_section = '.data'
            return index + 1
        elif token.value == '.bss':
            self.current_address = self.section_addresses['.bss']
            self.current_section = '.bss'
            return index + 1
        elif token.value == '.org':
            if index + 1 < len(self.tokens):
                next_token = self.tokens[index + 1]
                if next_token.type == TokenType.HEXIMMEDIATE:
                    self.current_address = hex_to_decimal(next_token.value)
                elif next_token.type == TokenType.DECIMMEDIATE:
                    self.current_address = int(next_token.value)
                return index + 2
            return index + 1
        elif token.value == '.byte':
            return self._handle_byte_directive(index)
        elif token.value == '.word':
            return self._handle_word_directive(index)
        elif token.value == '.string':
            return self._handle_string_directive(index)
        elif token.value == '.space':
            return self._handle_space_directive(index)
        
        return index + 1

    def _calculate_data_size(self, index: int) -> int:
        """Calculate size of data directive"""
        token = self.tokens[index]
        size = 0
        i = index + 1
        
        if token.value == '.byte':
            while i < len(self.tokens) and self.tokens[i].type in [TokenType.DECIMMEDIATE, TokenType.HEXIMMEDIATE, TokenType.COMMA]:
                if self.tokens[i].type != TokenType.COMMA:
                    size += 1
                i += 1
        elif token.value == '.word':
            while i < len(self.tokens) and self.tokens[i].type in [TokenType.DECIMMEDIATE, TokenType.HEXIMMEDIATE, TokenType.COMMA]:
                if self.tokens[i].type != TokenType.COMMA:
                    size += 2
                i += 1
        elif token.value in ['.string', '.ascii']:
            if i < len(self.tokens) and self.tokens[i].type == TokenType.STRING:
                size = len(self.tokens[i].value)
                if token.value == '.string':
                    size += 1  # null terminator
        
        return size

    def _handle_byte_directive(self, index: int) -> int:
        """Handle .byte directive"""
        i = index + 1
        while i < len(self.tokens):
            token = self.tokens[i]
            if token.type == TokenType.DECIMMEDIATE:
                value = int(token.value) & 0xFF
                self.memory[self.current_address] = value
                self.current_address += 1
            elif token.type == TokenType.HEXIMMEDIATE:
                value = hex_to_decimal(token.value) & 0xFF
                self.memory[self.current_address] = value
                self.current_address += 1
            elif token.type == TokenType.COMMA:
                pass  # Skip commas
            else:
                break
            i += 1
        return i

    def _handle_word_directive(self, index: int) -> int:
        """Handle .word directive"""
        i = index + 1
        while i < len(self.tokens):
            token = self.tokens[i]
            if token.type == TokenType.DECIMMEDIATE:
                value = int(token.value) & 0xFFFF
                self._write_word(self.current_address, value)
                self.current_address += 2
            elif token.type == TokenType.HEXIMMEDIATE:
                value = hex_to_decimal(token.value) & 0xFFFF
                self._write_word(self.current_address, value)
                self.current_address += 2
            elif token.type == TokenType.APPLABEL:
                # Forward reference - resolve in second pass
                if token.value in self.symbols:
                    value = self.symbols[token.value].value
                    self._write_word(self.current_address, value)
                    self.current_address += 2
                else:
                    print(f"Error: Undefined symbol '{token.value}'")
            elif token.type == TokenType.COMMA:
                pass  # Skip commas
            else:
                break
            i += 1
        return i

    def _handle_string_directive(self, index: int) -> int:
        """Handle .string directive"""
        if index + 1 < len(self.tokens) and self.tokens[index + 1].type == TokenType.STRING:
            string_data = self.tokens[index + 1].value
            for char in string_data:
                self.memory[self.current_address] = ord(char)
                self.current_address += 1
            # Add null terminator for .string
            self.memory[self.current_address] = 0
            self.current_address += 1
            return index + 2
        return index + 1

    def _handle_space_directive(self, index: int) -> int:
        """Handle .space directive"""
        if index + 1 < len(self.tokens) and self.tokens[index + 1].type == TokenType.DECIMMEDIATE:
            space_size = int(self.tokens[index + 1].value)
            # Memory is already zero-initialized
            self.current_address += space_size
            return index + 2
        return index + 1

    def _define_label(self, name: str, address: int):
        """Define a label symbol"""
        if name in self.symbols:
            print(f"Error: Label '{name}' already defined")
        else:
            self.symbols[name] = Symbol(name, address, True, False, self.current_section)

    def _get_register_number(self, reg_token: str) -> int:
        """Get register number from register token"""
        if reg_token.startswith('x'):
            return int(reg_token[1])
        return 0

    def _parse_immediate(self, token: Token) -> int:
        """Parse immediate value from token"""
        if token.type == TokenType.DECIMMEDIATE:
            return int(token.value)
        elif token.type == TokenType.HEXIMMEDIATE:
            return hex_to_decimal(token.value)
        elif token.type == TokenType.BINIMMEDIATE:
            return int(token.value[2:], 2)
        elif token.type == TokenType.APPLABEL:
            if token.value in self.symbols:
                return self.symbols[token.value].value
            else:
                print(f"Error: Undefined symbol '{token.value}'")
                return 0
        return 0

    def _encode_instruction(self, index: int) -> int:
        """Encode a base instruction"""
        token = self.tokens[index]
        mnemonic = token.value.lower()
        
        print(f"Encoding instruction: {mnemonic} at 0x{self.current_address:04X}")
        
        if mnemonic in self.r_type_encodings:
            return self._encode_r_type(index)
        elif mnemonic in self.i_type_encodings:
            return self._encode_i_type(index)
        elif mnemonic in self.b_type_encodings:
            return self._encode_b_type(index)
        elif mnemonic in self.s_type_encodings:
            return self._encode_s_type(index)
        elif mnemonic in self.l_type_encodings:
            return self._encode_l_type(index)
        elif mnemonic in ['j', 'jal']:
            return self._encode_j_type(index)
        elif mnemonic in ['lui', 'auipc']:
            return self._encode_u_type(index)
        elif mnemonic == 'ecall':
            return self._encode_sys_type(index)
        else:
            print(f"Error: Unknown instruction '{mnemonic}'")
            return index + 1

    def _encode_r_type(self, index: int) -> int:
        """Encode R-type instruction"""
        mnemonic = self.tokens[index].value.lower()
        encoding = self.r_type_encodings[mnemonic]
        
        # R-Type format: [15:12] funct4, [11:9] rs2, [8:6] rd/rs1, [5:3] func3, [2:0] 000
        if mnemonic in ['jr']:
            # JR rd - only one operand
            if index + 1 < len(self.tokens) and self.tokens[index + 1].type == TokenType.REGISTER:
                rd = self._get_register_number(self.tokens[index + 1].value)
                opcode = (encoding['funct4'] << 12) | (0 << 9) | (rd << 6) | (encoding['func3'] << 3) | 0x0
                self._write_word(self.current_address, opcode)
                self.current_address += 2
                return index + 2
        elif mnemonic in ['jalr']:
            # JALR rd, rs2 - two operands
            if (index + 3 < len(self.tokens) and 
                self.tokens[index + 1].type == TokenType.REGISTER and
                self.tokens[index + 2].type == TokenType.COMMA and
                self.tokens[index + 3].type == TokenType.REGISTER):
                
                rd = self._get_register_number(self.tokens[index + 1].value)
                rs2 = self._get_register_number(self.tokens[index + 3].value)
                opcode = (encoding['funct4'] << 12) | (rs2 << 9) | (rd << 6) | (encoding['func3'] << 3) | 0x0
                self._write_word(self.current_address, opcode)
                self.current_address += 2
                return index + 4
        else:
            # Standard R-type: rd, rs2 (rd is both destination and first source)
            if (index + 3 < len(self.tokens) and 
                self.tokens[index + 1].type == TokenType.REGISTER and
                self.tokens[index + 2].type == TokenType.COMMA and
                self.tokens[index + 3].type == TokenType.REGISTER):
                
                rd = self._get_register_number(self.tokens[index + 1].value)
                rs2 = self._get_register_number(self.tokens[index + 3].value)
                opcode = (encoding['funct4'] << 12) | (rs2 << 9) | (rd << 6) | (encoding['func3'] << 3) | 0x0
                self._write_word(self.current_address, opcode)
                self.current_address += 2
                return index + 4
        
        print(f"Error: Invalid R-type instruction format for {mnemonic}")
        return index + 1

    def _encode_i_type(self, index: int) -> int:
        """Encode I-type instruction"""
        mnemonic = self.tokens[index].value.lower()
        encoding = self.i_type_encodings[mnemonic]
        
        # I-Type format: [15:9] imm7, [8:6] rd/rs1, [5:3] func3, [2:0] 001
        if (index + 3 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER and
            self.tokens[index + 2].type == TokenType.COMMA):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            imm_token = self.tokens[index + 3]
            imm = self._parse_immediate(imm_token)
            
            # Handle shift instructions specially
            if mnemonic in ['slli', 'srli', 'srai']:
                shift_amount = imm & 0xF  # 4-bit shift amount
                shift_type = encoding['shift_type']
                imm7 = (shift_type << 4) | shift_amount
            else:
                # Sign extend to 7 bits
                imm7 = sign_extend(imm, 7) & 0x7F
            
            opcode = (imm7 << 9) | (rd << 6) | (encoding['func3'] << 3) | 0x1
            self._write_word(self.current_address, opcode)
            self.current_address += 2
            return index + 4
        
        print(f"Error: Invalid I-type instruction format for {mnemonic}")
        return index + 1

    def _encode_b_type(self, index: int) -> int:
        """Encode B-type instruction"""
        mnemonic = self.tokens[index].value.lower()
        encoding = self.b_type_encodings[mnemonic]
        
        # B-Type format: [15:12] imm[4:1], [11:9] rs2, [8:6] rs1, [5:3] func3, [2:0] 010
        if mnemonic in ['bz', 'bnz']:
            # BZ/BNZ rs1, label - only check rs1 against zero
            if (index + 3 < len(self.tokens) and 
                self.tokens[index + 1].type == TokenType.REGISTER and
                self.tokens[index + 2].type == TokenType.COMMA and
                self.tokens[index + 3].type == TokenType.APPLABEL):
                
                rs1 = self._get_register_number(self.tokens[index + 1].value)
                label_name = self.tokens[index + 3].value
                
                if label_name in self.symbols:
                    target_addr = self.symbols[label_name].value
                    offset = target_addr - (self.current_address + 2)  # PC+2 relative
                    offset_words = offset >> 1  # Convert to word offset
                    
                    # Check range for 5-bit signed offset (-16 to +15 words)
                    if offset_words < -16 or offset_words > 15:
                        print(f"Warning: Branch offset {offset} (0x{offset:04X}) exceeds 5-bit range at address 0x{self.current_address:04X}")
                    
                    # Take the lower 5 bits (this preserves sign for 5-bit two's complement)
                    offset_bits = offset_words & 0x1F
                    imm_high = (offset_bits >> 1) & 0xF  # bits [4:1]
                    
                    opcode = (imm_high << 12) | (0 << 9) | (rs1 << 6) | (encoding['func3'] << 3) | 0x2
                    self._write_word(self.current_address, opcode)
                    print(f"  Branch to {label_name}: offset={offset} (0x{offset:04X}), offset_words={offset_words}, offset_bits=0x{offset_bits:02X}")
                    self.current_address += 2
                    return index + 4
                else:
                    print(f"Error: Undefined label '{label_name}'")
        else:
            # Standard branch: rs1, rs2, label
            if (index + 5 < len(self.tokens) and 
                self.tokens[index + 1].type == TokenType.REGISTER and
                self.tokens[index + 2].type == TokenType.COMMA and
                self.tokens[index + 3].type == TokenType.REGISTER and
                self.tokens[index + 4].type == TokenType.COMMA and
                self.tokens[index + 5].type == TokenType.APPLABEL):
                
                rs1 = self._get_register_number(self.tokens[index + 1].value)
                rs2 = self._get_register_number(self.tokens[index + 3].value)
                label_name = self.tokens[index + 5].value
                
                if label_name in self.symbols:
                    target_addr = self.symbols[label_name].value
                    offset = target_addr - (self.current_address + 2)  # PC+2 relative
                    offset_words = offset >> 1  # Convert to word offset
                    
                    # Check range for 5-bit signed offset (-16 to +15 words)
                    if offset_words < -16 or offset_words > 15:
                        print(f"Warning: Branch offset {offset} (0x{offset:04X}) exceeds 5-bit range at address 0x{self.current_address:04X}")
                    
                    # Take the lower 5 bits (this preserves sign for 5-bit two's complement)
                    offset_bits = offset_words & 0x1F
                    imm_high = (offset_bits >> 1) & 0xF  # bits [4:1]
                    
                    opcode = (imm_high << 12) | (rs2 << 9) | (rs1 << 6) | (encoding['func3'] << 3) | 0x2
                    self._write_word(self.current_address, opcode)
                    print(f"  Branch to {label_name}: offset={offset} (0x{offset:04X}), offset_words={offset_words}, offset_bits=0x{offset_bits:02X}")
                    self.current_address += 2
                    return index + 6
                else:
                    print(f"Error: Undefined label '{label_name}'")
        
        print(f"Error: Invalid B-type instruction format for {mnemonic}")
        return index + 1

    def _encode_s_type(self, index: int) -> int:
        """Encode S-type instruction"""
        mnemonic = self.tokens[index].value.lower()
        encoding = self.s_type_encodings[mnemonic]
        
        # S-Type format: [15:12] imm[3:0], [11:9] rs2, [8:6] rs1, [5:3] func3, [2:0] 011
        # SW rs2, offset(rs1) or SW rs2, offset, rs1
        if self._is_memory_format(index + 2):
            # Format: SW rs2, offset(rs1)
            rs2 = self._get_register_number(self.tokens[index + 1].value)
            offset, rs1 = self._parse_memory_operand(index + 3)
            
            offset_bits = sign_extend(offset, 4) & 0xF
            opcode = (offset_bits << 12) | (rs2 << 9) | (rs1 << 6) | (encoding['func3'] << 3) | 0x3
            self._write_word(self.current_address, opcode)
            self.current_address += 2
            return self._skip_memory_operand(index + 3)
        
        print(f"Error: Invalid S-type instruction format for {mnemonic}")
        return index + 1

    def _encode_l_type(self, index: int) -> int:
        """Encode L-type instruction"""
        mnemonic = self.tokens[index].value.lower()
        encoding = self.l_type_encodings[mnemonic]
        
        # L-Type format: [15:12] imm[3:0], [11:9] rs2, [8:6] rd, [5:3] func3, [2:0] 100
        # LW rd, offset(rs2)
        if (index + 3 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER and
            self.tokens[index + 2].type == TokenType.COMMA and
            self._is_memory_format(index + 2)):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            offset, rs2 = self._parse_memory_operand(index + 3)
            
            offset_bits = sign_extend(offset, 4) & 0xF
            opcode = (offset_bits << 12) | (rs2 << 9) | (rd << 6) | (encoding['func3'] << 3) | 0x4
            self._write_word(self.current_address, opcode)
            self.current_address += 2
            return self._skip_memory_operand(index + 3)
        
        print(f"Error: Invalid L-type instruction format for {mnemonic}")
        return index + 1

    def _encode_j_type(self, index: int) -> int:
        """Encode J-type instruction"""
        mnemonic = self.tokens[index].value.lower()
        
        # J-Type format: [15] link, [14:9] imm[9:4], [8:6] rd, [5:3] imm[3:1], [2:0] 101
        if mnemonic == 'j':
            # J label
            if (index + 1 < len(self.tokens) and 
                self.tokens[index + 1].type == TokenType.APPLABEL):
                
                label_name = self.tokens[index + 1].value
                if label_name in self.symbols:
                    target_addr = self.symbols[label_name].value
                    offset = target_addr - (self.current_address + 2)  # PC+2 relative
                    offset_bits = (offset >> 1) & 0x3FF  # 10-bit signed offset, word-aligned
                    
                    imm_high = (offset_bits >> 4) & 0x3F  # bits [9:4]
                    imm_low = (offset_bits >> 1) & 0x7   # bits [3:1]
                    
                    opcode = (0 << 15) | (imm_high << 9) | (0 << 6) | (imm_low << 3) | 0x5
                    self._write_word(self.current_address, opcode)
                    self.current_address += 2
                    return index + 2
                else:
                    print(f"Error: Undefined label '{label_name}'")
        
        elif mnemonic == 'jal':
            # JAL rd, label
            if (index + 3 < len(self.tokens) and 
                self.tokens[index + 1].type == TokenType.REGISTER and
                self.tokens[index + 2].type == TokenType.COMMA and
                self.tokens[index + 3].type == TokenType.APPLABEL):
                
                rd = self._get_register_number(self.tokens[index + 1].value)
                label_name = self.tokens[index + 3].value
                
                if label_name in self.symbols:
                    target_addr = self.symbols[label_name].value
                    offset = target_addr - (self.current_address + 2)  # PC+2 relative
                    offset_bits = (offset >> 1) & 0x3FF  # 10-bit signed offset, word-aligned
                    
                    imm_high = (offset_bits >> 4) & 0x3F  # bits [9:4]
                    imm_low = (offset_bits >> 1) & 0x7   # bits [3:1]
                    
                    opcode = (1 << 15) | (imm_high << 9) | (rd << 6) | (imm_low << 3) | 0x5
                    self._write_word(self.current_address, opcode)
                    self.current_address += 2
                    return index + 4
                else:
                    print(f"Error: Undefined label '{label_name}'")
        
        print(f"Error: Invalid J-type instruction format for {mnemonic}")
        return index + 1

    def _encode_u_type(self, index: int) -> int:
        """Encode U-type instruction"""
        mnemonic = self.tokens[index].value.lower()
        
        # U-Type format: [15] flag, [14:9] imm[15:10], [8:6] rd, [5:3] imm[9:7], [2:0] 110
        if (index + 3 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER and
            self.tokens[index + 2].type == TokenType.COMMA):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            imm = self._parse_immediate(self.tokens[index + 3])
            
            # Extract immediate bits for U-type encoding
            imm_shifted = (imm >> 7) & 0x1FF  # 9-bit immediate (bits 15:7 of original)
            imm_high = (imm_shifted >> 3) & 0x3F  # bits [15:10] -> [14:9]
            imm_mid = imm_shifted & 0x7           # bits [9:7] -> [5:3]
            
            flag = 1 if mnemonic == 'auipc' else 0
            opcode = (flag << 15) | (imm_high << 9) | (rd << 6) | (imm_mid << 3) | 0x6
            self._write_word(self.current_address, opcode)
            self.current_address += 2
            return index + 4
        
        print(f"Error: Invalid U-type instruction format for {mnemonic}")
        return index + 1

    def _encode_sys_type(self, index: int) -> int:
        """Encode SYS-type instruction"""
        # SYS-Type format: [15:6] svc, [5:3] 000, [2:0] 111
        if index + 1 < len(self.tokens):
            svc = self._parse_immediate(self.tokens[index + 1])
            svc_bits = svc & 0x3FF  # 10-bit service number
            opcode = (svc_bits << 6) | (0 << 3) | 0x7
            self._write_word(self.current_address, opcode)
            self.current_address += 2
            return index + 2
        else:
            # ECALL with no service number (default to 0)
            opcode = (0 << 6) | (0 << 3) | 0x7
            self._write_word(self.current_address, opcode)
            self.current_address += 2
            return index + 1

    def _expand_pseudo_instruction(self, index: int) -> int:
        """Expand pseudo-instruction into base instructions"""
        token = self.tokens[index]
        mnemonic = token.value.lower()
        
        print(f"Expanding pseudo-instruction: {mnemonic}")
        
        if mnemonic == 'li16':
            return self._expand_li16(index)
        elif mnemonic == 'la':
            return self._expand_la(index)
        elif mnemonic == 'push':
            return self._expand_push(index)
        elif mnemonic == 'pop':
            return self._expand_pop(index)
        elif mnemonic == 'call':
            return self._expand_call(index)
        elif mnemonic == 'ret':
            return self._expand_ret(index)
        elif mnemonic == 'inc':
            return self._expand_inc(index)
        elif mnemonic == 'dec':
            return self._expand_dec(index)
        elif mnemonic == 'neg':
            return self._expand_neg(index)
        elif mnemonic == 'not':
            return self._expand_not(index)
        elif mnemonic == 'clr':
            return self._expand_clr(index)
        elif mnemonic == 'nop':
            return self._expand_nop(index)
        else:
            print(f"Error: Unknown pseudo-instruction '{mnemonic}'")
            return index + 1

    def _expand_li16(self, index: int) -> int:
        """Expand LI16 rd, imm16 -> LUI rd, high; ORI rd, low"""
        if (index + 3 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER and
            self.tokens[index + 2].type == TokenType.COMMA):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            imm16 = self._parse_immediate(self.tokens[index + 3])
            
            # Split into high and low parts
            high_part = (imm16 >> 7) & 0x1FF   # Upper 9 bits
            low_part = imm16 & 0x7F            # Lower 7 bits
            
            # LUI rd, high_part
            self._emit_u_type_instruction(0, high_part, rd)  # flag=0 for LUI
            
            # ORI rd, low_part
            self._emit_i_type_instruction(0x4, low_part, rd)  # func3=0x4 for ORI
            
            return index + 4
        
        print("Error: Invalid LI16 format")
        return index + 1

    def _expand_la(self, index: int) -> int:
        """Expand LA rd, label -> AUIPC rd, high; ADDI rd, low"""
        if (index + 3 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER and
            self.tokens[index + 2].type == TokenType.COMMA and
            self.tokens[index + 3].type == TokenType.APPLABEL):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            label_name = self.tokens[index + 3].value
            
            if label_name in self.symbols:
                target_addr = self.symbols[label_name].value
                offset = target_addr - self.current_address
                
                high_part = (offset >> 7) & 0x1FF
                low_part = offset & 0x7F
                
                # AUIPC rd, high_part
                self._emit_u_type_instruction(1, high_part, rd)  # flag=1 for AUIPC
                
                # ADDI rd, low_part
                self._emit_i_type_instruction(0x0, low_part, rd)  # func3=0x0 for ADDI
                
                return index + 4
            else:
                print(f"Error: Undefined label '{label_name}'")
        
        print("Error: Invalid LA format")
        return index + 1

    def _expand_push(self, index: int) -> int:
        """Expand PUSH rd -> ADDI sp, -2; SW rd, 0(sp)"""
        if (index + 1 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            sp = 2  # Stack pointer is x2
            
            # ADDI sp, -2
            self._emit_i_type_instruction(0x0, (-2) & 0x7F, sp)  # func3=0x0 for ADDI
            
            # SW rd, 0(sp)
            self._emit_s_type_instruction(0x1, 0, rd, sp)  # func3=0x1 for SW
            
            return index + 2
        
        print("Error: Invalid PUSH format")
        return index + 1

    def _expand_pop(self, index: int) -> int:
        """Expand POP rd -> LW rd, 0(sp); ADDI sp, 2"""
        if (index + 1 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            sp = 2  # Stack pointer is x2
            
            # LW rd, 0(sp)
            self._emit_l_type_instruction(0x1, 0, rd, sp)  # func3=0x1 for LW
            
            # ADDI sp, 2
            self._emit_i_type_instruction(0x0, 2, sp)  # func3=0x0 for ADDI
            
            return index + 2
        
        print("Error: Invalid POP format")
        return index + 1

    def _expand_call(self, index: int) -> int:
        """Expand CALL label -> JAL ra, label"""
        if (index + 1 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.APPLABEL):
            
            label_name = self.tokens[index + 1].value
            ra = 1  # Return address register is x1
            
            if label_name in self.symbols:
                target_addr = self.symbols[label_name].value
                offset = target_addr - (self.current_address + 2)
                offset_bits = (offset >> 1) & 0x3FF
                
                imm_high = (offset_bits >> 4) & 0x3F
                imm_low = (offset_bits >> 1) & 0x7
                
                # JAL ra, label
                opcode = (1 << 15) | (imm_high << 9) | (ra << 6) | (imm_low << 3) | 0x5
                self._write_word(self.current_address, opcode)
                self.current_address += 2
                
                return index + 2
            else:
                print(f"Error: Undefined label '{label_name}'")
        
        print("Error: Invalid CALL format")
        return index + 1

    def _expand_ret(self, index: int) -> int:
        """Expand RET -> JR ra"""
        ra = 1  # Return address register is x1
        
        # JR ra
        self._emit_r_type_instruction(0xB, 0x0, 0, ra)  # funct4=0xB, func3=0x0 for JR
        
        return index + 1

    def _expand_inc(self, index: int) -> int:
        """Expand INC rd -> ADDI rd, 1"""
        if (index + 1 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            
            # ADDI rd, 1
            self._emit_i_type_instruction(0x0, 1, rd)  # func3=0x0 for ADDI
            
            return index + 2
        
        print("Error: Invalid INC format")
        return index + 1

    def _expand_dec(self, index: int) -> int:
        """Expand DEC rd -> ADDI rd, -1"""
        if (index + 1 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            
            # ADDI rd, -1
            self._emit_i_type_instruction(0x0, (-1) & 0x7F, rd)  # func3=0x0 for ADDI
            
            return index + 2
        
        print("Error: Invalid DEC format")
        return index + 1

    def _expand_neg(self, index: int) -> int:
        """Expand NEG rd -> XORI rd, -1; ADDI rd, 1"""
        if (index + 1 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            
            # XORI rd, -1 (invert all bits)
            self._emit_i_type_instruction(0x6, 0x7F, rd)  # func3=0x6 for XORI, -1 = 0x7F
            
            # ADDI rd, 1
            self._emit_i_type_instruction(0x0, 1, rd)  # func3=0x0 for ADDI
            
            return index + 2
        
        print("Error: Invalid NEG format")
        return index + 1

    def _expand_not(self, index: int) -> int:
        """Expand NOT rd -> XORI rd, -1"""
        if (index + 1 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            
            # XORI rd, -1 (invert all bits)
            self._emit_i_type_instruction(0x6, 0x7F, rd)  # func3=0x6 for XORI, -1 = 0x7F
            
            return index + 2
        
        print("Error: Invalid NOT format")
        return index + 1

    def _expand_clr(self, index: int) -> int:
        """Expand CLR rd -> XOR rd, rd"""
        if (index + 1 < len(self.tokens) and 
            self.tokens[index + 1].type == TokenType.REGISTER):
            
            rd = self._get_register_number(self.tokens[index + 1].value)
            
            # XOR rd, rd (clear register)
            self._emit_r_type_instruction(0x9, 0x6, rd, rd)  # funct4=0x9, func3=0x6 for XOR
            
            return index + 2
        
        print("Error: Invalid CLR format")
        return index + 1

    def _expand_nop(self, index: int) -> int:
        """Expand NOP -> ADD x0, x0"""
        # ADD x0, x0 (does nothing useful)
        self._emit_r_type_instruction(0x0, 0x0, 0, 0)  # funct4=0x0, func3=0x0 for ADD
        
        return index + 1

    # Helper methods for emitting instructions
    def _emit_r_type_instruction(self, funct4: int, func3: int, rs2: int, rd: int):
        """Emit R-type instruction"""
        opcode = (funct4 << 12) | (rs2 << 9) | (rd << 6) | (func3 << 3) | 0x0
        self._write_word(self.current_address, opcode)
        self.current_address += 2

    def _emit_i_type_instruction(self, func3: int, imm7: int, rd: int):
        """Emit I-type instruction"""
        opcode = ((imm7 & 0x7F) << 9) | (rd << 6) | (func3 << 3) | 0x1
        self._write_word(self.current_address, opcode)
        self.current_address += 2

    def _emit_s_type_instruction(self, func3: int, imm4: int, rs2: int, rs1: int):
        """Emit S-type instruction"""
        opcode = ((imm4 & 0xF) << 12) | (rs2 << 9) | (rs1 << 6) | (func3 << 3) | 0x3
        self._write_word(self.current_address, opcode)
        self.current_address += 2

    def _emit_l_type_instruction(self, func3: int, imm4: int, rd: int, rs2: int):
        """Emit L-type instruction"""
        opcode = ((imm4 & 0xF) << 12) | (rs2 << 9) | (rd << 6) | (func3 << 3) | 0x4
        self._write_word(self.current_address, opcode)
        self.current_address += 2

    def _emit_u_type_instruction(self, flag: int, imm9: int, rd: int):
        """Emit U-type instruction"""
        imm_high = (imm9 >> 3) & 0x3F
        imm_mid = imm9 & 0x7
        opcode = (flag << 15) | (imm_high << 9) | (rd << 6) | (imm_mid << 3) | 0x6
        self._write_word(self.current_address, opcode)
        self.current_address += 2

    # Memory operand parsing helpers
    def _is_memory_format(self, index: int) -> bool:
        """Check if token sequence represents memory operand like offset(reg)"""
        if index + 1 < len(self.tokens):
            # Look for pattern: immediate ( register )
            next_token = self.tokens[index + 1]
            return (next_token.type in [TokenType.DECIMMEDIATE, TokenType.HEXIMMEDIATE] and
                    index + 3 < len(self.tokens) and
                    self.tokens[index + 2].type == TokenType.LPAREN and
                    self.tokens[index + 3].type == TokenType.REGISTER)
        return False

    def _parse_memory_operand(self, index: int) -> Tuple[int, int]:
        """Parse memory operand like offset(reg) and return (offset, reg_num)"""
        offset = self._parse_immediate(self.tokens[index])
        reg_num = self._get_register_number(self.tokens[index + 2].value)
        return offset, reg_num

    def _skip_memory_operand(self, index: int) -> int:
        """Skip past a memory operand and return next index"""
        # Skip: immediate ( register )
        return index + 4

    def _write_word(self, address: int, value: int):
        """Write a 16-bit word to memory (little-endian)"""
        if 0 <= address < len(self.memory) - 1:
            self.memory[address] = value & 0xFF
            self.memory[address + 1] = (value >> 8) & 0xFF
            print(f"  Written 0x{value:04X} to address 0x{address:04X}")
        else:
            print(f"Error: Address 0x{address:04X} out of range")

    def save_binary(self, filename: str):
        """Save assembled code as binary file"""
        with open(filename, 'wb') as f:
            f.write(self.memory)
        print(f"Binary saved to {filename}")

    def save_hex(self, filename: str):
        """Save assembled code as Intel HEX file"""
        with open(filename, 'w') as f:
            # Find the extent of used memory
            start_addr = 0
            end_addr = len(self.memory)
            
            # Find first non-zero byte
            for i in range(len(self.memory)):
                if self.memory[i] != 0:
                    start_addr = i
                    break
            
            # Find last non-zero byte
            for i in range(len(self.memory) - 1, -1, -1):
                if self.memory[i] != 0:
                    end_addr = i + 1
                    break
            
            # Write Intel HEX records
            addr = start_addr
            while addr < end_addr:
                # Write up to 16 bytes per record
                record_len = min(16, end_addr - addr)
                data_bytes = self.memory[addr:addr + record_len]
                
                # Calculate checksum
                checksum = record_len + ((addr >> 8) & 0xFF) + (addr & 0xFF)
                for byte_val in data_bytes:
                    checksum += byte_val
                checksum = (~checksum + 1) & 0xFF
                
                # Write record
                f.write(f":{record_len:02X}{addr:04X}00")
                for byte_val in data_bytes:
                    f.write(f"{byte_val:02X}")
                f.write(f"{checksum:02X}\n")
                
                addr += record_len
            
            # Write end record
            f.write(":00000001FF\n")
        
        print(f"Intel HEX saved to {filename}")

    def print_listing(self):
        """Print assembly listing"""
        print("\n=== Assembly Listing ===")
        print("Address  Machine Code  Assembly")
        print("-------  ------------  --------")
        
        # Print non-zero memory locations
        for addr in range(0, len(self.memory), 2):
            if self.memory[addr] != 0 or self.memory[addr + 1] != 0:
                word = self.memory[addr] | (self.memory[addr + 1] << 8)
                print(f"{addr:04X}     {word:04X}          # Data at 0x{addr:04X}")


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python zx16_assembler.py <input_file> [options]")
        print("Options:")
        print("  -o <output>     Output file (default: input.bin)")
        print("  -f <format>     Output format: bin, hex (default: bin)")
        print("  -l              Generate listing")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = None
    output_format = "bin"
    generate_listing = False
    
    # Parse command line arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '-o' and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-f' and i + 1 < len(sys.argv):
            output_format = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-l':
            generate_listing = True
            i += 1
        else:
            print(f"Unknown option: {sys.argv[i]}")
            i += 1
    
    # Default output file
    if output_file is None:
        base_name = Path(input_file).stem
        if output_format == "hex":
            output_file = f"{base_name}.hex"
        else:
            output_file = f"{base_name}.bin"
    
    # Read input file
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            source_code = f.read().splitlines()
    except Exception as e:
        print(f"Error: Unable to open file '{input_file}'. {e}")
        sys.exit(1)
    
    # Assemble
    assembler = ZX16Assembler()
    try:
        assembler.assemble(source_code)
        
        # Generate output
        if output_format == "hex":
            assembler.save_hex(output_file)
        else:
            assembler.save_binary(output_file)
        
        # Generate listing if requested
        if generate_listing:
            assembler.print_listing()
        
        print(f"\nAssembly completed successfully.")
        print(f"Output written to: {output_file}")
        
    except Exception as e:
        print(f"Assembly failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()