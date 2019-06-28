from .fields import *

BITMAPS = {
    0x01: (ByteField(), 'timeout', 'binary time-out'),
    0x02: (ByteField(), 'max_status_infos', 'binary max.status infos'),
    0x03: (ByteField(), 'service_byte', 'binary service-byte'),
    0x04: (BCDIntField(length=6), 'amount', 'Amount'),
    0x05: (ByteField(), 'pump_nr', 'binary pump-Nr.'),
    0x06: (TLVField(), 'tlv', 'TLV'),
    0x0B: (BCDField(length=3), 'trace_number', 'trace-number'),
    0x0C: (BCDField(length=3), 'time', 'Time'),
    0x0D: (BCDField(length=2), 'date_day', 'date, MM DD (see AA)'),
    0x0E: (BCDField(length=2), 'card_expire', 'expiry-date, YY MM'),
    0x17: (
        BCDField(length=2), 'card_sequence_number', 'card sequence-number'),
    0x19: (
        ByteField(), 'payment_type',
        'binary status-byte/payment-type/card-type'),
    0x22: (
        LLVARField(), 'card_number',
        'card_number, PAN / EF_ID, \'E\' used to indicate masked numeric '
        'digit'),
    0x23: (
        LLVARField(), 'track_2',
        'track 2 data, \'E\' used to indicate masked numeric digit1'),
    0x24: (
        LLLVARField(), 'track_3',
        'track 3 data, \'E\' used to indicate masked numeric digit1'),
    0x27: (ByteField(), 'result_code', 'binary result-code'),
    0x29: (BCDField(length=4), 'tid', 'TID'),
    0x2A: (FixedLengthField(length=15), 'vu', 'ASCII VU-number'),
    0x2D: (LLVARField(), 'track_1', 'track 1 data'),
    0x2E: (LLLVARField(), 'sync_chip_data', 'sychronous chip data'),
    0x37: (
        BCDField(length=3), 'trace_number_original',
        'trace-number of the original transaction for reversal'),
    0x3A: (
        BCDField(length=2), 'cvv',
        'the field cvv is optionally used for mail order'),
    0x3B: (FixedLengthField(length=8), 'aid', 'AID authorisation-attribute'),
    0x3C: (
        LLLVARField(), 'additional', 'additional-data/additional-text'),
    0x3D: (PasswordField(), 'password', 'Password'),
    0x49: (BCDIntField(length=2), 'currency_code', 'currency code'),
    0x60: (LLLVARField(), 'totals', 'individual totals'),
    0x87: (BCDField(length=2), 'receipt', 'receipt-number'),
    0x88: (BCDField(length=3), 'turnover', 'turnover record number'),
    0x8A: (
        ByteField(), 'card_type',
        'binary card-type (card-number according to ZVT-protocol; comparison '
        '8C)'),
    0x8B: (LLVARField(), 'card_name', 'card-name'),
    0x8C: (
        ByteField(), 'card_operator',
        'binary card-type-ID of the network operator (comparison 8A)'),
    0x92: (
        LLLVARField(), 'offline_chip',
        'additional-data ec-Cash with chip offline'),
    0x9A: (
        LLLVARField(), 'geldkarte',
        'Geldkarte payments-/ failed-payment record/total record Geldkarte'),
    0xA0: (ByteField(), 'result_code_as', 'binary result-code-AS'),
    0xA7: (LLVARField(), 'chip_ef_id', 'chip-data, EF_ID'),
    0xAA: (BCDField(length=3), 'date', 'date YY MM DD (see 0D)'),
    0xAF: (LLLVARField(), 'ef_info', 'EF_Info'),
    0xBA: (FixedLengthField(length=5), 'aid_param', 'binary AID-parameter'),
    0xD0: (ByteField(), 'algo_key', 'binary algorithm-Key'),
    0xD1: (LLVARField(), 'offset', 'card offset/PIN-data'),
    0xD2: (ByteField(), 'direction', 'binary direction'),
    0xD3: (ByteField(), 'key_position', 'binary key-position'),
    0xE0: (ByteField(), 'input_min', 'binary min. length of the input'),
    0xE1: (LLStringField(), 'iline1', 'text2 line 1'),
    0xE2: (LLStringField(), 'iline2', 'text2 line 2'),
    0xE3: (LLStringField(), 'iline3', 'text2 line 3'),
    0xE4: (LLStringField(), 'iline4', 'text2 line 4'),
    0xE5: (LLStringField(), 'iline5', 'text2 line 5'),
    0xE6: (LLStringField(), 'iline6', 'text2 line 6'),
    0xE7: (LLStringField(), 'iline7', 'text2 line 7'),
    0xE8: (LLStringField(), 'iline8', 'text2 line 8'),
    0xE9: (
        ByteField(), 'max_input_length',
        "binary max. length of the input"),
    0xEA: (ByteField(), 'input_echo', "binary echo the Input"),
    0xEB: (FixedLengthField(length=8), 'mac', "binary MAC over text 1 and text 2"),
    0xF0: (ByteField(), 'display_duration', "binary display-duration"),
    0xF1: (LLStringField(), 'line1', "text1 line 1"),
    0xF2: (LLStringField(), 'line2', "text1 line 2"),
    0xF3: (LLStringField(), 'line3', "text1 line 3"),
    0xF4: (LLStringField(), 'line4', "text1 line 4"),
    0xF5: (LLStringField(), 'line5', "text1 line 5"),
    0xF6: (LLStringField(), 'line6', "text1 line 6"),
    0xF7: (LLStringField(), 'line7', "text1 line 7"),
    0xF8: (LLStringField(), 'line8', "text1 line 8"),
    0xF9: (ByteField(), 'beeps', "binary number of beep-tones"),
    0xFA: (ByteField(), 'status', "binary status"),
    0xFB: (
        ByteField(), 'ok_required',
        "binary confirmation the input with <OK> required"),
    0xFC: (ByteField(), 'dialog_control', "binary dialog-control"),
}
