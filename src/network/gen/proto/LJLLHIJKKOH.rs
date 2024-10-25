// This file is generated by rust-protobuf 3.4.0. Do not edit
// .proto file is parsed by pure
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `LJLLHIJKKOH.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

// @@protoc_insertion_point(message:LJLLHIJKKOH)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct LJLLHIJKKOH {
    // message fields
    // @@protoc_insertion_point(field:LJLLHIJKKOH.DBKHFAEKNKL)
    pub DBKHFAEKNKL: u32,
    // @@protoc_insertion_point(field:LJLLHIJKKOH.CBAHJJCOGLM)
    pub CBAHJJCOGLM: ::std::vec::Vec<u32>,
    // @@protoc_insertion_point(field:LJLLHIJKKOH.HHMFMFHCMOK)
    pub HHMFMFHCMOK: ::std::vec::Vec<super::KLIKDPDIJMI::KLIKDPDIJMI>,
    // @@protoc_insertion_point(field:LJLLHIJKKOH.GNGFBJNJMIA)
    pub GNGFBJNJMIA: bool,
    // @@protoc_insertion_point(field:LJLLHIJKKOH.DJMKFKNCPJP)
    pub DJMKFKNCPJP: u32,
    // @@protoc_insertion_point(field:LJLLHIJKKOH.JIBAEJKHDJA)
    pub JIBAEJKHDJA: u32,
    // @@protoc_insertion_point(field:LJLLHIJKKOH.ADBHBEEHCMJ)
    pub ADBHBEEHCMJ: u32,
    // @@protoc_insertion_point(field:LJLLHIJKKOH.GNNDAONOLIA)
    pub GNNDAONOLIA: u32,
    // @@protoc_insertion_point(field:LJLLHIJKKOH.avatar_list)
    pub avatar_list: ::std::vec::Vec<u32>,
    // @@protoc_insertion_point(field:LJLLHIJKKOH.FAHCBPNFKFO)
    pub FAHCBPNFKFO: u32,
    // special fields
    // @@protoc_insertion_point(special_field:LJLLHIJKKOH.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a LJLLHIJKKOH {
    fn default() -> &'a LJLLHIJKKOH {
        <LJLLHIJKKOH as ::protobuf::Message>::default_instance()
    }
}

impl LJLLHIJKKOH {
    pub fn new() -> LJLLHIJKKOH {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(10);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "DBKHFAEKNKL",
            |m: &LJLLHIJKKOH| { &m.DBKHFAEKNKL },
            |m: &mut LJLLHIJKKOH| { &mut m.DBKHFAEKNKL },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "CBAHJJCOGLM",
            |m: &LJLLHIJKKOH| { &m.CBAHJJCOGLM },
            |m: &mut LJLLHIJKKOH| { &mut m.CBAHJJCOGLM },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "HHMFMFHCMOK",
            |m: &LJLLHIJKKOH| { &m.HHMFMFHCMOK },
            |m: &mut LJLLHIJKKOH| { &mut m.HHMFMFHCMOK },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "GNGFBJNJMIA",
            |m: &LJLLHIJKKOH| { &m.GNGFBJNJMIA },
            |m: &mut LJLLHIJKKOH| { &mut m.GNGFBJNJMIA },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "DJMKFKNCPJP",
            |m: &LJLLHIJKKOH| { &m.DJMKFKNCPJP },
            |m: &mut LJLLHIJKKOH| { &mut m.DJMKFKNCPJP },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "JIBAEJKHDJA",
            |m: &LJLLHIJKKOH| { &m.JIBAEJKHDJA },
            |m: &mut LJLLHIJKKOH| { &mut m.JIBAEJKHDJA },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "ADBHBEEHCMJ",
            |m: &LJLLHIJKKOH| { &m.ADBHBEEHCMJ },
            |m: &mut LJLLHIJKKOH| { &mut m.ADBHBEEHCMJ },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "GNNDAONOLIA",
            |m: &LJLLHIJKKOH| { &m.GNNDAONOLIA },
            |m: &mut LJLLHIJKKOH| { &mut m.GNNDAONOLIA },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "avatar_list",
            |m: &LJLLHIJKKOH| { &m.avatar_list },
            |m: &mut LJLLHIJKKOH| { &mut m.avatar_list },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "FAHCBPNFKFO",
            |m: &LJLLHIJKKOH| { &m.FAHCBPNFKFO },
            |m: &mut LJLLHIJKKOH| { &mut m.FAHCBPNFKFO },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<LJLLHIJKKOH>(
            "LJLLHIJKKOH",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for LJLLHIJKKOH {
    const NAME: &'static str = "LJLLHIJKKOH";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                80 => {
                    self.DBKHFAEKNKL = is.read_uint32()?;
                },
                26 => {
                    is.read_repeated_packed_uint32_into(&mut self.CBAHJJCOGLM)?;
                },
                24 => {
                    self.CBAHJJCOGLM.push(is.read_uint32()?);
                },
                90 => {
                    self.HHMFMFHCMOK.push(is.read_message()?);
                },
                8 => {
                    self.GNGFBJNJMIA = is.read_bool()?;
                },
                32 => {
                    self.DJMKFKNCPJP = is.read_uint32()?;
                },
                56 => {
                    self.JIBAEJKHDJA = is.read_uint32()?;
                },
                96 => {
                    self.ADBHBEEHCMJ = is.read_uint32()?;
                },
                48 => {
                    self.GNNDAONOLIA = is.read_uint32()?;
                },
                106 => {
                    is.read_repeated_packed_uint32_into(&mut self.avatar_list)?;
                },
                104 => {
                    self.avatar_list.push(is.read_uint32()?);
                },
                112 => {
                    self.FAHCBPNFKFO = is.read_uint32()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if self.DBKHFAEKNKL != 0 {
            my_size += ::protobuf::rt::uint32_size(10, self.DBKHFAEKNKL);
        }
        for value in &self.CBAHJJCOGLM {
            my_size += ::protobuf::rt::uint32_size(3, *value);
        };
        for value in &self.HHMFMFHCMOK {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        };
        if self.GNGFBJNJMIA != false {
            my_size += 1 + 1;
        }
        if self.DJMKFKNCPJP != 0 {
            my_size += ::protobuf::rt::uint32_size(4, self.DJMKFKNCPJP);
        }
        if self.JIBAEJKHDJA != 0 {
            my_size += ::protobuf::rt::uint32_size(7, self.JIBAEJKHDJA);
        }
        if self.ADBHBEEHCMJ != 0 {
            my_size += ::protobuf::rt::uint32_size(12, self.ADBHBEEHCMJ);
        }
        if self.GNNDAONOLIA != 0 {
            my_size += ::protobuf::rt::uint32_size(6, self.GNNDAONOLIA);
        }
        for value in &self.avatar_list {
            my_size += ::protobuf::rt::uint32_size(13, *value);
        };
        if self.FAHCBPNFKFO != 0 {
            my_size += ::protobuf::rt::uint32_size(14, self.FAHCBPNFKFO);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if self.DBKHFAEKNKL != 0 {
            os.write_uint32(10, self.DBKHFAEKNKL)?;
        }
        for v in &self.CBAHJJCOGLM {
            os.write_uint32(3, *v)?;
        };
        for v in &self.HHMFMFHCMOK {
            ::protobuf::rt::write_message_field_with_cached_size(11, v, os)?;
        };
        if self.GNGFBJNJMIA != false {
            os.write_bool(1, self.GNGFBJNJMIA)?;
        }
        if self.DJMKFKNCPJP != 0 {
            os.write_uint32(4, self.DJMKFKNCPJP)?;
        }
        if self.JIBAEJKHDJA != 0 {
            os.write_uint32(7, self.JIBAEJKHDJA)?;
        }
        if self.ADBHBEEHCMJ != 0 {
            os.write_uint32(12, self.ADBHBEEHCMJ)?;
        }
        if self.GNNDAONOLIA != 0 {
            os.write_uint32(6, self.GNNDAONOLIA)?;
        }
        for v in &self.avatar_list {
            os.write_uint32(13, *v)?;
        };
        if self.FAHCBPNFKFO != 0 {
            os.write_uint32(14, self.FAHCBPNFKFO)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> LJLLHIJKKOH {
        LJLLHIJKKOH::new()
    }

    fn clear(&mut self) {
        self.DBKHFAEKNKL = 0;
        self.CBAHJJCOGLM.clear();
        self.HHMFMFHCMOK.clear();
        self.GNGFBJNJMIA = false;
        self.DJMKFKNCPJP = 0;
        self.JIBAEJKHDJA = 0;
        self.ADBHBEEHCMJ = 0;
        self.GNNDAONOLIA = 0;
        self.avatar_list.clear();
        self.FAHCBPNFKFO = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static LJLLHIJKKOH {
        static instance: LJLLHIJKKOH = LJLLHIJKKOH {
            DBKHFAEKNKL: 0,
            CBAHJJCOGLM: ::std::vec::Vec::new(),
            HHMFMFHCMOK: ::std::vec::Vec::new(),
            GNGFBJNJMIA: false,
            DJMKFKNCPJP: 0,
            JIBAEJKHDJA: 0,
            ADBHBEEHCMJ: 0,
            GNNDAONOLIA: 0,
            avatar_list: ::std::vec::Vec::new(),
            FAHCBPNFKFO: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for LJLLHIJKKOH {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("LJLLHIJKKOH").unwrap()).clone()
    }
}

impl ::std::fmt::Display for LJLLHIJKKOH {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for LJLLHIJKKOH {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x11LJLLHIJKKOH.proto\x1a\x11KLIKDPDIJMI.proto\"\xee\x02\n\x0bLJLLHIJK\
    KOH\x12\x20\n\x0bDBKHFAEKNKL\x18\n\x20\x01(\rR\x0bDBKHFAEKNKL\x12\x20\n\
    \x0bCBAHJJCOGLM\x18\x03\x20\x03(\rR\x0bCBAHJJCOGLM\x12.\n\x0bHHMFMFHCMOK\
    \x18\x0b\x20\x03(\x0b2\x0c.KLIKDPDIJMIR\x0bHHMFMFHCMOK\x12\x20\n\x0bGNGF\
    BJNJMIA\x18\x01\x20\x01(\x08R\x0bGNGFBJNJMIA\x12\x20\n\x0bDJMKFKNCPJP\
    \x18\x04\x20\x01(\rR\x0bDJMKFKNCPJP\x12\x20\n\x0bJIBAEJKHDJA\x18\x07\x20\
    \x01(\rR\x0bJIBAEJKHDJA\x12\x20\n\x0bADBHBEEHCMJ\x18\x0c\x20\x01(\rR\x0b\
    ADBHBEEHCMJ\x12\x20\n\x0bGNNDAONOLIA\x18\x06\x20\x01(\rR\x0bGNNDAONOLIA\
    \x12\x1f\n\x0bavatar_list\x18\r\x20\x03(\rR\navatarList\x12\x20\n\x0bFAH\
    CBPNFKFO\x18\x0e\x20\x01(\rR\x0bFAHCBPNFKFOb\x06proto3\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(1);
            deps.push(super::KLIKDPDIJMI::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(1);
            messages.push(LJLLHIJKKOH::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(0);
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}