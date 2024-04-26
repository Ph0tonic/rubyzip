# frozen_string_literal: true

module Zip
  module AesEncryption # :nodoc:

    ENCRYPTION_VERSION_AE_1 = 0x01
    ENCRYPTION_VERSION_AE_2 = 0x02

    ENCRYPTION_VERSIONS = [
      ENCRYPTION_VERSION_AE_1,
      ENCRYPTION_VERSION_AE_2
    ]

    ENCRYPTION_STRENGHT_128_BIT = 0x01
    ENCRYPTION_STRENGHT_192_BIT = 0x02
    ENCRYPTION_STRENGHT_256_BIT = 0x03

    ENCRYPTION_STRENGHTS = [
      ENCRYPTION_STRENGHT_128_BIT,
      ENCRYPTION_STRENGHT_192_BIT,
      ENCRYPTION_STRENGHT_256_BIT
    ]

    SALT_SIZES = {
      ENCRYPTION_STRENGHT_128_BIT => 8,
      ENCRYPTION_STRENGHT_192_BIT => 12,
      ENCRYPTION_STRENGHT_256_BIT => 16,
    }

    def initialize(password, encryption_strength, encryption_version)
      @password = password
      raise "Invalid encryption strength" unless ENCRYPTION_STRENGHTS.include? encryption_strength
      raise "Invalid encryption version" unless ENCRYPTION_VERSIONS.include? encryption_version

      @encryption_strength = encryption_strength
      @encryption_version = encryption_version
      # reset_keys!
    end

    def header_bytesize
      SALT_SIZES[@encryption_strength] + 2
    end

    def gp_flags
      0x0001
    end

    protected

    # def reset_keys!
    #   @key0 = 0x12345678
    #   @key1 = 0x23456789
    #   @key2 = 0x34567890
    #   @password.each_byte do |byte|
    #     update_keys(byte.chr)
    #   end
    # end

    # def update_keys(num)
    #   @key0 = ~Zlib.crc32(num, ~@key0)
    #   @key1 = (((@key1 + (@key0 & 0xff)) * 134_775_813) + 1) & 0xffffffff
    #   @key2 = ~Zlib.crc32((@key1 >> 24).chr, ~@key2)
    # end

    # def decrypt_byte
    #   temp = (@key2 & 0xffff) | 2
    #   ((temp * (temp ^ 1)) >> 8) & 0xff
    # end
  end

  class AesEncrypter < Encrypter # :nodoc:
    include AesEncryption

    def header(mtime)
      [].tap do |header|
        (header_bytesize - 2).times do
          header << Random.rand(0..255)
        end
        header << (mtime.to_binary_dos_time & 0xff)
        header << (mtime.to_binary_dos_time >> 8)
      end.map { |x| encode x }.pack('C*')
    end

    def encrypt(data)
      data.unpack('C*').map { |x| encode x }.pack('C*')
    end

    def data_descriptor(crc32, compressed_size, uncompressed_size)
      [0x08074b50, crc32, compressed_size, uncompressed_size].pack('VVVV')
    end

    def reset!
      reset_keys!
    end

    private

    def encode(num)
      t = decrypt_byte
      update_keys(num.chr)
      t ^ num
    end
  end

  class AesDecrypter < Decrypter # :nodoc:
    include AesEncryption

    def decrypt(data)
      data.unpack('C*').map { |x| decode x }.pack('C*')
    end

    def reset!(header)
      reset_keys!
      header.each_byte do |x|
        decode x
      end
    end

    private

    def decode(num)
      num ^= decrypt_byte
      update_keys(num.chr)
      num
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
