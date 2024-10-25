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

//! Generated file from `LFEHJFJHJLH.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

// @@protoc_insertion_point(message:LFEHJFJHJLH)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct LFEHJFJHJLH {
    // message fields
    // @@protoc_insertion_point(field:LFEHJFJHJLH.IJEPENGMPLG)
    pub IJEPENGMPLG: u32,
    // @@protoc_insertion_point(field:LFEHJFJHJLH.IDIEPEFFGIC)
    pub IDIEPEFFGIC: u32,
    // @@protoc_insertion_point(field:LFEHJFJHJLH.BNNIJDPHLMN)
    pub BNNIJDPHLMN: u32,
    // @@protoc_insertion_point(field:LFEHJFJHJLH.GABPEMANANE)
    pub GABPEMANANE: ::std::vec::Vec<super::GGLAGEOBBGK::GGLAGEOBBGK>,
    // @@protoc_insertion_point(field:LFEHJFJHJLH.KEEIDHOGDNJ)
    pub KEEIDHOGDNJ: ::std::vec::Vec<super::LOGGJGCLNNI::LOGGJGCLNNI>,
    // @@protoc_insertion_point(field:LFEHJFJHJLH.LKAHLGNIECF)
    pub LKAHLGNIECF: bool,
    // @@protoc_insertion_point(field:LFEHJFJHJLH.LLNGIIGOMKO)
    pub LLNGIIGOMKO: ::std::vec::Vec<super::IDFECBMCHMA::IDFECBMCHMA>,
    // special fields
    // @@protoc_insertion_point(special_field:LFEHJFJHJLH.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a LFEHJFJHJLH {
    fn default() -> &'a LFEHJFJHJLH {
        <LFEHJFJHJLH as ::protobuf::Message>::default_instance()
    }
}

impl LFEHJFJHJLH {
    pub fn new() -> LFEHJFJHJLH {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(7);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "IJEPENGMPLG",
            |m: &LFEHJFJHJLH| { &m.IJEPENGMPLG },
            |m: &mut LFEHJFJHJLH| { &mut m.IJEPENGMPLG },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "IDIEPEFFGIC",
            |m: &LFEHJFJHJLH| { &m.IDIEPEFFGIC },
            |m: &mut LFEHJFJHJLH| { &mut m.IDIEPEFFGIC },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "BNNIJDPHLMN",
            |m: &LFEHJFJHJLH| { &m.BNNIJDPHLMN },
            |m: &mut LFEHJFJHJLH| { &mut m.BNNIJDPHLMN },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "GABPEMANANE",
            |m: &LFEHJFJHJLH| { &m.GABPEMANANE },
            |m: &mut LFEHJFJHJLH| { &mut m.GABPEMANANE },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "KEEIDHOGDNJ",
            |m: &LFEHJFJHJLH| { &m.KEEIDHOGDNJ },
            |m: &mut LFEHJFJHJLH| { &mut m.KEEIDHOGDNJ },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "LKAHLGNIECF",
            |m: &LFEHJFJHJLH| { &m.LKAHLGNIECF },
            |m: &mut LFEHJFJHJLH| { &mut m.LKAHLGNIECF },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "LLNGIIGOMKO",
            |m: &LFEHJFJHJLH| { &m.LLNGIIGOMKO },
            |m: &mut LFEHJFJHJLH| { &mut m.LLNGIIGOMKO },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<LFEHJFJHJLH>(
            "LFEHJFJHJLH",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for LFEHJFJHJLH {
    const NAME: &'static str = "LFEHJFJHJLH";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                40 => {
                    self.IJEPENGMPLG = is.read_uint32()?;
                },
                112 => {
                    self.IDIEPEFFGIC = is.read_uint32()?;
                },
                120 => {
                    self.BNNIJDPHLMN = is.read_uint32()?;
                },
                34 => {
                    self.GABPEMANANE.push(is.read_message()?);
                },
                98 => {
                    self.KEEIDHOGDNJ.push(is.read_message()?);
                },
                72 => {
                    self.LKAHLGNIECF = is.read_bool()?;
                },
                106 => {
                    self.LLNGIIGOMKO.push(is.read_message()?);
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
        if self.IJEPENGMPLG != 0 {
            my_size += ::protobuf::rt::uint32_size(5, self.IJEPENGMPLG);
        }
        if self.IDIEPEFFGIC != 0 {
            my_size += ::protobuf::rt::uint32_size(14, self.IDIEPEFFGIC);
        }
        if self.BNNIJDPHLMN != 0 {
            my_size += ::protobuf::rt::uint32_size(15, self.BNNIJDPHLMN);
        }
        for value in &self.GABPEMANANE {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        };
        for value in &self.KEEIDHOGDNJ {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        };
        if self.LKAHLGNIECF != false {
            my_size += 1 + 1;
        }
        for value in &self.LLNGIIGOMKO {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if self.IJEPENGMPLG != 0 {
            os.write_uint32(5, self.IJEPENGMPLG)?;
        }
        if self.IDIEPEFFGIC != 0 {
            os.write_uint32(14, self.IDIEPEFFGIC)?;
        }
        if self.BNNIJDPHLMN != 0 {
            os.write_uint32(15, self.BNNIJDPHLMN)?;
        }
        for v in &self.GABPEMANANE {
            ::protobuf::rt::write_message_field_with_cached_size(4, v, os)?;
        };
        for v in &self.KEEIDHOGDNJ {
            ::protobuf::rt::write_message_field_with_cached_size(12, v, os)?;
        };
        if self.LKAHLGNIECF != false {
            os.write_bool(9, self.LKAHLGNIECF)?;
        }
        for v in &self.LLNGIIGOMKO {
            ::protobuf::rt::write_message_field_with_cached_size(13, v, os)?;
        };
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> LFEHJFJHJLH {
        LFEHJFJHJLH::new()
    }

    fn clear(&mut self) {
        self.IJEPENGMPLG = 0;
        self.IDIEPEFFGIC = 0;
        self.BNNIJDPHLMN = 0;
        self.GABPEMANANE.clear();
        self.KEEIDHOGDNJ.clear();
        self.LKAHLGNIECF = false;
        self.LLNGIIGOMKO.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static LFEHJFJHJLH {
        static instance: LFEHJFJHJLH = LFEHJFJHJLH {
            IJEPENGMPLG: 0,
            IDIEPEFFGIC: 0,
            BNNIJDPHLMN: 0,
            GABPEMANANE: ::std::vec::Vec::new(),
            KEEIDHOGDNJ: ::std::vec::Vec::new(),
            LKAHLGNIECF: false,
            LLNGIIGOMKO: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for LFEHJFJHJLH {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("LFEHJFJHJLH").unwrap()).clone()
    }
}

impl ::std::fmt::Display for LFEHJFJHJLH {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for LFEHJFJHJLH {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x11LFEHJFJHJLH.proto\x1a\x11GGLAGEOBBGK.proto\x1a\x11IDFECBMCHMA.prot\
    o\x1a\x11LOGGJGCLNNI.proto\"\xa5\x02\n\x0bLFEHJFJHJLH\x12\x20\n\x0bIJEPE\
    NGMPLG\x18\x05\x20\x01(\rR\x0bIJEPENGMPLG\x12\x20\n\x0bIDIEPEFFGIC\x18\
    \x0e\x20\x01(\rR\x0bIDIEPEFFGIC\x12\x20\n\x0bBNNIJDPHLMN\x18\x0f\x20\x01\
    (\rR\x0bBNNIJDPHLMN\x12.\n\x0bGABPEMANANE\x18\x04\x20\x03(\x0b2\x0c.GGLA\
    GEOBBGKR\x0bGABPEMANANE\x12.\n\x0bKEEIDHOGDNJ\x18\x0c\x20\x03(\x0b2\x0c.\
    LOGGJGCLNNIR\x0bKEEIDHOGDNJ\x12\x20\n\x0bLKAHLGNIECF\x18\t\x20\x01(\x08R\
    \x0bLKAHLGNIECF\x12.\n\x0bLLNGIIGOMKO\x18\r\x20\x03(\x0b2\x0c.IDFECBMCHM\
    AR\x0bLLNGIIGOMKOb\x06proto3\
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
            let mut deps = ::std::vec::Vec::with_capacity(3);
            deps.push(super::GGLAGEOBBGK::file_descriptor().clone());
            deps.push(super::IDFECBMCHMA::file_descriptor().clone());
            deps.push(super::LOGGJGCLNNI::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(1);
            messages.push(LFEHJFJHJLH::generated_message_descriptor_data());
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