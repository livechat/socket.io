/*!
 * socket.io-node
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */
 
/**
 * Module requirements.
 */

var Transport = require('../../transport')
  , EventEmitter = process.EventEmitter
  , crypto = require('crypto')
  , url = require('url')
  , parser = require('../../parser')
  , zlib = require('zlib')
  , util = require('../../util');

/**
 * Export the constructor.
 */

exports = module.exports = WebSocket;
exports.Parser = Parser;

/**
 * HTTP interface constructor. Interface compatible with all transports that
 * depend on request-response cycles.
 *
 * @api public
 */

function WebSocket (mng, data, req) {
  // parser
  var self = this;

  this.manager = mng;
  this.parser = new Parser();
  this.parser.on('data', function (packet) {
    self.onMessage(parser.decodePacket(packet));
  });
  this.parser.on('ping', function () {
    // version 8 ping => pong
    try {
      self.socket.write('\u008a\u0000');
    }
    catch (e) {
      self.end();
      return;
    }
  });
  this.parser.on('close', function () {
    self.end();
  });
  this.parser.on('error', function (reason) {
    self.log.warn(self.name + ' parser error: ' + reason);
    self.end();
  });
  this.encodeQueue = [];
  this.threshold = 50;
  this.processing = false;
  Transport.call(this, mng, data, req);
};

/**
 * Inherits from Transport.
 */

WebSocket.prototype.__proto__ = Transport.prototype;

/**
 * Transport name
 *
 * @api public
 */

WebSocket.prototype.name = 'websocket';

/**
 * Websocket draft version
 *
 * @api public
 */

WebSocket.prototype.protocolVersion = '16';

/**
 * Called when the socket connects.
 *
 * @api private
 */

WebSocket.prototype.onSocketConnect = function () {
  var self = this;

  if (typeof this.req.headers.upgrade === 'undefined' || 
      this.req.headers.upgrade.toLowerCase() !== 'websocket') {
    this.log.warn(this.name + ' connection invalid');
    this.end();
    return;
  }

  var origin = this.req.headers['origin'] || ''
    , location = ((this.manager.settings['match origin protocol'] ?
                      origin.match(/^https/) : this.socket.encrypted) ?
                        'wss' : 'ws')
               + '://' + this.req.headers.host + this.req.url;
  
  if (!this.verifyOrigin(origin)) {
    this.log.warn(this.name + ' connection invalid: origin mismatch');
    this.end();
    return;    
  }
  
  if (!this.req.headers['sec-websocket-key']) {
    this.log.warn(this.name + ' connection invalid: received no key');
    this.end();
    return;
  }
    
  // calc key
  var key = this.req.headers['sec-websocket-key'];  
  var shasum = crypto.createHash('sha1');  
  shasum.update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");  
  key = shasum.digest('base64');

  var headers = [
      'HTTP/1.1 101 Switching Protocols'
    , 'Upgrade: websocket'
    , 'Connection: Upgrade'
    , 'Sec-WebSocket-Accept: ' + key
  ];

  if (this.req.headers['sec-websocket-extensions']){
    var extensions = this.req.headers['sec-websocket-extensions'].split(';');
    if (extensions.indexOf('permessage-deflate') !== -1){
      this.rsv1 = true;
      headers.push('Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=15; client_no_context_takeover; server_no_context_takeover');
    }
  }

  try {
    this.socket.write(headers.concat('', '').join('\r\n'));
    this.socket.setTimeout(0);
    this.socket.setNoDelay(true);
  } catch (e) {
    this.end();
    return;
  }

  this.socket.on('data', function (data) {
    self.parser.add(data);
  });
};

/**
 * Verifies the origin of a request.
 *
 * @api private
 */

WebSocket.prototype.verifyOrigin = function (origin) {
  var origins = this.manager.get('origins');

  if (origin === 'null') origin = '*';

  if (origins.indexOf('*:*') !== -1) {
    return true;
  }

  if (origin) {
    try {
      var parts = url.parse(origin);
      parts.port = parts.port || 80;
      var ok =
        ~origins.indexOf(parts.hostname + ':' + parts.port) ||
        ~origins.indexOf(parts.hostname + ':*') ||
        ~origins.indexOf('*:' + parts.port);
      if (!ok) this.log.warn('illegal origin: ' + origin);
      return ok;
    } catch (ex) {
      this.log.warn('error parsing origin');
    }
  }
  else {
    this.log.warn('origin missing from websocket call, yet required by config');        
  }
  return false;
};

/**
 * Prepares data to write
 *
 * @api private
 */

WebSocket.prototype.write = function (data){
  this.handleEncodeQueue(data);
}

WebSocket.prototype.socketWrite = function (frame) {

  if (this.open) {
    try {
      this.socket.write(frame, 'binary');
    }
    catch (e) {
      this.end();
      return;
    }
    this.log.debug(this.name + ' writing', frame);
  }
};

/**
 * Handles zlib queue
 *
 * @api private
 */

WebSocket.prototype.handleEncodeQueue = function (data){

  if (data){
    if (this.rsv1){
      this.encodeQueue.push([data, {rsv1: true}]);
    }else{
      this.encodeQueue.push([data, {rsv1: false}]);
    }
  }

  
  if (!this.processing){
    var packet = this.encodeQueue.shift()
    if (packet){
      this.encode.call(this, packet[0], packet[1]);
    }
  }
};

/**
 * Deflates message
 *
 * @api private
 */

WebSocket.prototype.deflate = function (data, callback){
  var i=0;
  var buffers = [];

  var def = zlib.createDeflateRaw({flush:zlib.Z_FULL_FLUSH});

  def.on('end', function(){
    buffer = Buffer.concat(buffers);
    buffer = buffer.slice(0, buffer.length - 6);
    callback(null, buffer);
    def.removeAllListeners()
  });

  def.on('data', function(buffer){
    buffers.push(buffer);
  });

  def.on('error', function(e){
    callback(e);
  });

  def.write(data);
  def.end();

};

/**
 * Deflates message
 *
 * @api private
 */

WebSocket.prototype.encode = function (data, options){

  var self = this;
  if (options.rsv1 && this.threshold < data.length){
    this.processing = true;
    this.deflate(data, function (err, packed){
      if (err){
        self.emit('close');
        self.reset();
      }else{
        self.socketWrite.call(self, self.frame(0xC1, packed));
        self.processing = false;
        self.handleEncodeQueue.call(self);
      }
    });
  }else{
    this.socketWrite.call(self, self.frame(0x81, data));
  }
};

/**
 * Writes a payload.
 *
 * @api private
 */

WebSocket.prototype.payload = function (msgs) {
  for (var i = 0, l = msgs.length; i < l; i++) {
    this.handleEncodeQueue.call(this, msgs[i]);
  }

  return this;
};

/**
 * Frame server-to-client output as a text packet.
 *
 * @api private
 */

WebSocket.prototype.frame = function (opcode, str) {
  
  if (str instanceof Buffer){
    var dataBuffer = str;
  }else{
    var dataBuffer = new Buffer(str)  
  }
  
  var dataLength = dataBuffer.length
    , startOffset = 2
    , secondByte = dataLength;
  if (dataLength > 65536) {
    startOffset = 10;
    secondByte = 127;
  }
  else if (dataLength > 125) {
    startOffset = 4;
    secondByte = 126;
  }
  var outputBuffer = new Buffer(dataLength + startOffset);
  outputBuffer[0] = opcode;
  outputBuffer[1] = secondByte;
  dataBuffer.copy(outputBuffer, startOffset);
  switch (secondByte) {
  case 126:
    outputBuffer[2] = dataLength >>> 8;
    outputBuffer[3] = dataLength % 256;
    break;
  case 127:
    var l = dataLength;
    for (var i = 1; i <= 8; ++i) {
      outputBuffer[startOffset - i] = l & 0xff;
      l >>>= 8;
    }
  }
  return outputBuffer;
};

/**
 * Closes the connection.
 *
 * @api private
 */

WebSocket.prototype.doClose = function () {
  this.socket.end();
};

/**
 * WebSocket parser
 *
 * @api public
 */
 
function Parser () {
  this.state = {
    activeFragmentedOperation: null,
    lastFragment: false,
    masked: false,
    opcode: 0,
    rsv1: false 
  };
  this.overflow = null;
  this.expectOffset = 0;
  this.expectBuffer = null;
  this.expectHandler = null;
  this.currentMessage = '';
  this.decodeQueue = [];

  var self = this;  
  this.opcodeHandlers = {
    // text
    '1': function(data) {
      var finish = function(mask, data) {
        self.currentMessage += self.unmask(mask, data);
        if (self.state.lastFragment) {
          self.handleDecodeQueue.call(self,'data', self.currentMessage, {rsv1: self.state.rsv1, rawMessage: data});
          self.currentMessage = '';
        }
        self.endPacket();
      }

      var expectData = function(length) {
        if (self.state.masked) {
          self.expect('Mask', 4, function(data) {
            var mask = data;
            self.expect('Data', length, function(data) {
              finish(mask, data);
            });
          });
        }
        else {
          self.expect('Data', length, function(data) { 
            finish(null, data);
          });
        } 
      }

      // decode length
      var firstLength = data[1] & 0x7f;
      if (firstLength < 126) {
        expectData(firstLength);
      }
      else if (firstLength == 126) {
        self.expect('Length', 2, function(data) {
          expectData(util.unpack(data));
        });
      }
      else if (firstLength == 127) {
        self.expect('Length', 8, function(data) {
          if (util.unpack(data.slice(0, 4)) != 0) {
            self.error('packets with length spanning more than 32 bit is currently not supported');
            return;
          }
          var lengthBytes = data.slice(4); // note: cap to 32 bit length
          expectData(util.unpack(data));
        });
      }      
    },
    // binary
    '2': function(data) {
      var finish = function(mask, data) {
        if (typeof self.currentMessage == 'string') self.currentMessage = []; // build a buffer list
        self.currentMessage.push(self.unmask(mask, data, true));
        if (self.state.lastFragment) {
          self.handleDecodeQueue.call(self, 'binary', self.concatBuffers(self.currentMessage), {binary: true,});
          self.currentMessage = '';
        }
        self.endPacket();
      }

      var expectData = function(length) {
        if (self.state.masked) {
          self.expect('Mask', 4, function(data) {
            var mask = data;
            self.expect('Data', length, function(data) {
              finish(mask, data);
            });
          });
        }
        else {
          self.expect('Data', length, function(data) { 
            finish(null, data);
          });
        } 
      }

      // decode length
      var firstLength = data[1] & 0x7f;
      if (firstLength < 126) {
        expectData(firstLength);
      }
      else if (firstLength == 126) {
        self.expect('Length', 2, function(data) {
          expectData(util.unpack(data));
        });
      }
      else if (firstLength == 127) {
        self.expect('Length', 8, function(data) {
          if (util.unpack(data.slice(0, 4)) != 0) {
            self.error('packets with length spanning more than 32 bit is currently not supported');
            return;
          }
          var lengthBytes = data.slice(4); // note: cap to 32 bit length
          expectData(util.unpack(data));
        });
      }      
    },
    // close
    '8': function(data) {
      self.emit('close');
      self.reset();
    },
    // ping
    '9': function(data) {
      if (self.state.lastFragment == false) {
        self.error('fragmented ping is not supported');
        return;
      }
      
      var finish = function(mask, data) {
        self.handleDecodeQueue.call(self, 'ping', self.unmask(mask, data), {rawMessage:data});
        self.endPacket();
      }

      var expectData = function(length) {
        if (self.state.masked) {
          self.expect('Mask', 4, function(data) {
            var mask = data;
            self.expect('Data', length, function(data) {
              finish(mask, data);
            });
          });
        }
        else {
          self.expect('Data', length, function(data) { 
            finish(null, data);
          });
        } 
      }

      // decode length
      var firstLength = data[1] & 0x7f;
      if (firstLength == 0) {
        finish(null, null);        
      }
      else if (firstLength < 126) {
        expectData(firstLength);
      }
      else if (firstLength == 126) {
        self.expect('Length', 2, function(data) {
          expectData(util.unpack(data));
        });
      }
      else if (firstLength == 127) {
        self.expect('Length', 8, function(data) {
          expectData(util.unpack(data));
        });
      }      
    }
  }

  this.expect('Opcode', 2, this.processPacket);  
};

/**
 * Inherits from EventEmitter.
 */

Parser.prototype.__proto__ = EventEmitter.prototype;

/**
 * Add new data to the parser.
 *
 * @api public
 */

Parser.prototype.add = function(data) {
  if (this.expectBuffer == null) {
    this.addToOverflow(data);
    return;
  }
  var toRead = Math.min(data.length, this.expectBuffer.length - this.expectOffset);
  data.copy(this.expectBuffer, this.expectOffset, 0, toRead);
  this.expectOffset += toRead;
  if (toRead < data.length) {
    // at this point the overflow buffer shouldn't at all exist
    this.overflow = new Buffer(data.length - toRead);
    data.copy(this.overflow, 0, toRead, toRead + this.overflow.length);
  }
  if (this.expectOffset == this.expectBuffer.length) {
    var bufferForHandler = this.expectBuffer;
    this.expectBuffer = null;
    this.expectOffset = 0;
    this.expectHandler.call(this, bufferForHandler);
  }
}

/**
 * Adds a piece of data to the overflow.
 *
 * @api private
 */

Parser.prototype.addToOverflow = function(data) {
  if (this.overflow == null) this.overflow = data;
  else {
    var prevOverflow = this.overflow;
    this.overflow = new Buffer(this.overflow.length + data.length);
    prevOverflow.copy(this.overflow, 0);
    data.copy(this.overflow, prevOverflow.length);
  }  
}

/**
 * Waits for a certain amount of bytes to be available, then fires a callback.
 *
 * @api private
 */

Parser.prototype.expect = function(what, length, handler) {
  this.expectBuffer = new Buffer(length);
  this.expectOffset = 0;
  this.expectHandler = handler;
  if (this.overflow != null) {
    var toOverflow = this.overflow;
    this.overflow = null;
    this.add(toOverflow);
  }
}

/**
 * Start processing a new packet.
 *
 * @api private
 */

Parser.prototype.processPacket = function (data) {
  if ((data[0] & 0x30) != 0) {
    this.error('reserved fields must be empty');
    return;
  }

  if (!this.state.rsv1 && (data[0] & 0x40) != 0){
    this.state.rsv1 = true;
  }

  this.state.lastFragment = (data[0] & 0x80) == 0x80; 
  this.state.masked = (data[1] & 0x80) == 0x80;
  var opcode = data[0] & 0xf;
  if (opcode == 0) { 
    // continuation frame
    this.state.opcode = this.state.activeFragmentedOperation;
    if (!(this.state.opcode == 1 || this.state.opcode == 2)) {
      this.error('continuation frame cannot follow current opcode')
      return;
    }
  }
  else {    
    this.state.opcode = opcode;
    if (this.state.lastFragment === false) {
        this.state.activeFragmentedOperation = opcode;
    }
  }
  var handler = this.opcodeHandlers[this.state.opcode];
  if (typeof handler == 'undefined') this.error('no handler for opcode ' + this.state.opcode);
  else handler(data);
}

/**
 * Endprocessing a packet.
 *
 * @api private
 */

Parser.prototype.endPacket = function() {
  this.expectOffset = 0;
  this.expectBuffer = null;
  this.expectHandler = null;
  this.state.rsv1 = false;
  if (this.state.lastFragment && this.state.opcode == this.state.activeFragmentedOperation) {
    // end current fragmented operation
    this.state.activeFragmentedOperation = null;
  }
  this.state.lastFragment = false;
  this.state.opcode = this.state.activeFragmentedOperation != null ? this.state.activeFragmentedOperation : 0;
  this.state.masked = false;
  this.expect('Opcode', 2, this.processPacket);  
}

/**
 * Reset the parser state.
 *
 * @api private
 */

Parser.prototype.reset = function() {
  this.state = {
    activeFragmentedOperation: null,
    lastFragment: false,
    masked: false,
    opcode: 0,
    rsv1: false
  };
  this.decodeQueue = [];
  this.expectOffset = 0;
  this.expectBuffer = null;
  this.expectHandler = null;
  this.overflow = null;
  this.currentMessage = '';
  this.processing = false;
}

/**
 * Unmask received data.
 *
 * @api private
 */

Parser.prototype.unmask = function (mask, buf, binary) {
  if (mask != null) {
    for (var i = 0, ll = buf.length; i < ll; i++) {
      buf[i] ^= mask[i % 4];
    }    
  }
  if (binary) return buf;
  return buf != null ? buf.toString('utf8') : '';
}

/**
 * Concatenates a list of buffers.
 *
 * @api private
 */

Parser.prototype.concatBuffers = function(buffers) {
  var length = 0;
  for (var i = 0, l = buffers.length; i < l; ++i) {
    length += buffers[i].length;
  }
  var mergedBuffer = new Buffer(length);
  var offset = 0;
  for (var i = 0, l = buffers.length; i < l; ++i) {
    buffers[i].copy(mergedBuffer, offset);
    offset += buffers[i].length;
  }
  return mergedBuffer;
}

/**
 * Handles an error
 *
 * @api private
 */

Parser.prototype.error = function (reason) {
  this.reset();
  this.emit('error', reason);
  return this;
};

Parser.prototype.handleDecodeQueue = function (type, message, options){
  if (type){
    this.decodeQueue.push([type, message, options]);
  }

  
  if (!this.processing){
    var packet = this.decodeQueue.shift();
    if (packet){
      this.decode.call(this, packet[0], packet[1], packet[2]);
    }
  }
}

Parser.prototype.decode = function (type, message, options){
  var self = this;

  if (!message){
    return this.emit(type);
  }

  if (options.rsv1){
    this.processing = true;

    zlib.inflateRaw.call(self, options.rawMessage, function(err, extracted){
      if (options.binary){
        var message = extracted;
      }else{
        var message = extracted.toString('utf8');
      }

      self.emit(type, message);
      self.processing = false;
      self.handleDecodeQueue.call(self);

    });
  }else{
    this.emit(type, message);
  }
};