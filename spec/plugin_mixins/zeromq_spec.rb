# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require 'logstash/plugin_mixins/zeromq'

class Dummy < LogStash::Inputs::Base
  attr_accessor :mode

  def set_logger(logger)
   @logger = logger
  end

  include LogStash::PluginMixins::ZeroMQ
  def server?
    @mode == "server"
  end
end

describe LogStash::PluginMixins::ZeroMQ do
  let(:basic_config) { {} }
  let(:impl) {
    d = Dummy.new(basic_config)
    d.mode = "server"
    d
  }
  let(:tracer) { double("logger") }

  it "should initialize with no extra settings" do
    expect {
      impl
    }.not_to raise_error
  end

  it "should return a ZMQ context" do
    expect(impl.context).to be_a ZMQ::Context
  end

  context "when setup" do
    let(:socket) { context = ZMQ::Context.new; context.socket(ZMQ::REQ) }
    let(:port) { rand(1000)+1025 }
    after do
      socket.close
    end

    context "a server" do
      it "should setup a server, bind to address without error" do
        expect { impl.setup(socket, "tcp://127.0.0.1:#{port}") }.to_not raise_error
      end

      it "a 'bound' info line is logged" do
        allow(tracer).to receive(:debug)
        impl.set_logger(tracer)  
        expect(tracer).to receive(:info).with("0mq: bound", {:address=>"tcp://127.0.0.1:#{port}"})
        impl.setup(socket, "tcp://127.0.0.1:#{port}")
      end
    end

    context "a client" do
      let(:impl_client) {
        d = Dummy.new(basic_config)
        d.mode = "client"
        d
      }

      it "a 'connected' info line is logged" do
        allow(tracer).to receive(:debug)
        impl_client.set_logger(tracer) 
        expect(tracer).to receive(:info).with("0mq: connected", {:address=>"tcp://127.0.0.1:#{port}"})
        impl_client.setup(socket, "tcp://127.0.0.1:#{port}")
      end

      it "should setup a client, connecting to address without error" do
        expect { impl_client.setup(socket, "tcp://127.0.0.1:#{port}") }.to_not raise_error
      end
    end
  end

  context "when error_check" do
    it "should not raise an error for return code 0 or greater" do
      expect { impl.error_check(0, "test return values" ) }.to_not raise_error
      expect { impl.error_check(1, "test return values" ) }.to_not raise_error
    end
    it "should raise an error for return code below 0" do
      expect { impl.error_check(-1, "test return values" ) }.to raise_error
      expect { impl.error_check(-999, "test return values" ) }.to raise_error
    end

    it "should raise an error for ZMQ::EAGAIN if eagain_not_error=false" do
      allow(ZMQ::Util).to receive(:errno).and_return(ZMQ::EAGAIN)
      expect { impl.error_check(-1, "test return values", false) }.to raise_error
    end

    it "should not raise an error for ZMQ::EAGAIN if eagain_not_error=true" do
      allow(ZMQ::Util).to receive(:errno).and_return(ZMQ::EAGAIN)
      expect { impl.error_check(-1, "test return values", true) }.to_not raise_error
    end
  end

  context "when socketopts" do
    let(:socket) { context = ZMQ::Context.new; context.socket(ZMQ::REQ) }
    after do
      socket.close
    end

    it "should set SNDHWM to numeric value without error" do
      expect { impl.setopts(socket, { "ZMQ::SNDHWM" => "50" } ) }.to_not raise_error
    end
    it "should raise an error if set SNDHWM to a non numeric value" do
      expect { impl.setopts(socket, { "ZMQ::SNDHWM" => "foo" } ) }.to raise_error
    end
    it "should raise an error for unknown ZMQ option" do
      expect { impl.setopts(socket, { "ZMQ::UNKNOWNOPT" => "foo" } ) }.to raise_error
    end
    it "should set IDENTITY to string value without error" do
      expect { impl.setopts(socket, { "ZMQ::IDENTITY" => "my_named_queue" } ) }.to_not raise_error
    end
    it "should raise an error for a wrong formated ZMQ option" do
      expect { impl.setopts(socket, { "ZMQ..SNDHWM" => "50" } ) }.to raise_error
    end
    it "should set multiple options" do
      expect { impl.setopts(socket, { "ZMQ::SNDHWM" => "50", "ZMQ::SNDBUF" => "50" } ) }.to_not raise_error
    end
  end
end
