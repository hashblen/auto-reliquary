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

//! Generated file from `NECPIBKAFJE.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

// @@protoc_insertion_point(message:NECPIBKAFJE)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct NECPIBKAFJE {
    // message fields
    // @@protoc_insertion_point(field:NECPIBKAFJE.LBPJJFNLMFC)
    pub LBPJJFNLMFC: u32,
    // @@protoc_insertion_point(field:NECPIBKAFJE.PMJMDJEAGAF)
    pub PMJMDJEAGAF: i32,
    // @@protoc_insertion_point(field:NECPIBKAFJE.PININKABAJB)
    pub PININKABAJB: u32,
    // @@protoc_insertion_point(field:NECPIBKAFJE.id)
    pub id: u32,
    // @@protoc_insertion_point(field:NECPIBKAFJE.ONDPGANOLJA)
    pub ONDPGANOLJA: i32,
    // @@protoc_insertion_point(field:NECPIBKAFJE.NFGDGCIPKNE)
    pub NFGDGCIPKNE: ::std::vec::Vec<u32>,
    // @@protoc_insertion_point(field:NECPIBKAFJE.CNNEMJIJNEB)
    pub CNNEMJIJNEB: u32,
    // @@protoc_insertion_point(field:NECPIBKAFJE.OCPEDKAHCLO)
    pub OCPEDKAHCLO: ::std::vec::Vec<u32>,
    // @@protoc_insertion_point(field:NECPIBKAFJE.BBANNHGDFEF)
    pub BBANNHGDFEF: ::protobuf::MessageField<super::LPHBEMJDGKA::LPHBEMJDGKA>,
    // special fields
    // @@protoc_insertion_point(special_field:NECPIBKAFJE.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a NECPIBKAFJE {
    fn default() -> &'a NECPIBKAFJE {
        <NECPIBKAFJE as ::protobuf::Message>::default_instance()
    }
}

impl NECPIBKAFJE {
    pub fn new() -> NECPIBKAFJE {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(9);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "LBPJJFNLMFC",
            |m: &NECPIBKAFJE| { &m.LBPJJFNLMFC },
            |m: &mut NECPIBKAFJE| { &mut m.LBPJJFNLMFC },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "PMJMDJEAGAF",
            |m: &NECPIBKAFJE| { &m.PMJMDJEAGAF },
            |m: &mut NECPIBKAFJE| { &mut m.PMJMDJEAGAF },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "PININKABAJB",
            |m: &NECPIBKAFJE| { &m.PININKABAJB },
            |m: &mut NECPIBKAFJE| { &mut m.PININKABAJB },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "id",
            |m: &NECPIBKAFJE| { &m.id },
            |m: &mut NECPIBKAFJE| { &mut m.id },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "ONDPGANOLJA",
            |m: &NECPIBKAFJE| { &m.ONDPGANOLJA },
            |m: &mut NECPIBKAFJE| { &mut m.ONDPGANOLJA },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "NFGDGCIPKNE",
            |m: &NECPIBKAFJE| { &m.NFGDGCIPKNE },
            |m: &mut NECPIBKAFJE| { &mut m.NFGDGCIPKNE },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "CNNEMJIJNEB",
            |m: &NECPIBKAFJE| { &m.CNNEMJIJNEB },
            |m: &mut NECPIBKAFJE| { &mut m.CNNEMJIJNEB },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "OCPEDKAHCLO",
            |m: &NECPIBKAFJE| { &m.OCPEDKAHCLO },
            |m: &mut NECPIBKAFJE| { &mut m.OCPEDKAHCLO },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::LPHBEMJDGKA::LPHBEMJDGKA>(
            "BBANNHGDFEF",
            |m: &NECPIBKAFJE| { &m.BBANNHGDFEF },
            |m: &mut NECPIBKAFJE| { &mut m.BBANNHGDFEF },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<NECPIBKAFJE>(
            "NECPIBKAFJE",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for NECPIBKAFJE {
    const NAME: &'static str = "NECPIBKAFJE";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                64 => {
                    self.LBPJJFNLMFC = is.read_uint32()?;
                },
                72 => {
                    self.PMJMDJEAGAF = is.read_int32()?;
                },
                120 => {
                    self.PININKABAJB = is.read_uint32()?;
                },
                88 => {
                    self.id = is.read_uint32()?;
                },
                96 => {
                    self.ONDPGANOLJA = is.read_int32()?;
                },
                18 => {
                    is.read_repeated_packed_uint32_into(&mut self.NFGDGCIPKNE)?;
                },
                16 => {
                    self.NFGDGCIPKNE.push(is.read_uint32()?);
                },
                24 => {
                    self.CNNEMJIJNEB = is.read_uint32()?;
                },
                42 => {
                    is.read_repeated_packed_uint32_into(&mut self.OCPEDKAHCLO)?;
                },
                40 => {
                    self.OCPEDKAHCLO.push(is.read_uint32()?);
                },
                82 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.BBANNHGDFEF)?;
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
        if self.LBPJJFNLMFC != 0 {
            my_size += ::protobuf::rt::uint32_size(8, self.LBPJJFNLMFC);
        }
        if self.PMJMDJEAGAF != 0 {
            my_size += ::protobuf::rt::int32_size(9, self.PMJMDJEAGAF);
        }
        if self.PININKABAJB != 0 {
            my_size += ::protobuf::rt::uint32_size(15, self.PININKABAJB);
        }
        if self.id != 0 {
            my_size += ::protobuf::rt::uint32_size(11, self.id);
        }
        if self.ONDPGANOLJA != 0 {
            my_size += ::protobuf::rt::int32_size(12, self.ONDPGANOLJA);
        }
        for value in &self.NFGDGCIPKNE {
            my_size += ::protobuf::rt::uint32_size(2, *value);
        };
        if self.CNNEMJIJNEB != 0 {
            my_size += ::protobuf::rt::uint32_size(3, self.CNNEMJIJNEB);
        }
        for value in &self.OCPEDKAHCLO {
            my_size += ::protobuf::rt::uint32_size(5, *value);
        };
        if let Some(v) = self.BBANNHGDFEF.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if self.LBPJJFNLMFC != 0 {
            os.write_uint32(8, self.LBPJJFNLMFC)?;
        }
        if self.PMJMDJEAGAF != 0 {
            os.write_int32(9, self.PMJMDJEAGAF)?;
        }
        if self.PININKABAJB != 0 {
            os.write_uint32(15, self.PININKABAJB)?;
        }
        if self.id != 0 {
            os.write_uint32(11, self.id)?;
        }
        if self.ONDPGANOLJA != 0 {
            os.write_int32(12, self.ONDPGANOLJA)?;
        }
        for v in &self.NFGDGCIPKNE {
            os.write_uint32(2, *v)?;
        };
        if self.CNNEMJIJNEB != 0 {
            os.write_uint32(3, self.CNNEMJIJNEB)?;
        }
        for v in &self.OCPEDKAHCLO {
            os.write_uint32(5, *v)?;
        };
        if let Some(v) = self.BBANNHGDFEF.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(10, v, os)?;
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

    fn new() -> NECPIBKAFJE {
        NECPIBKAFJE::new()
    }

    fn clear(&mut self) {
        self.LBPJJFNLMFC = 0;
        self.PMJMDJEAGAF = 0;
        self.PININKABAJB = 0;
        self.id = 0;
        self.ONDPGANOLJA = 0;
        self.NFGDGCIPKNE.clear();
        self.CNNEMJIJNEB = 0;
        self.OCPEDKAHCLO.clear();
        self.BBANNHGDFEF.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static NECPIBKAFJE {
        static instance: NECPIBKAFJE = NECPIBKAFJE {
            LBPJJFNLMFC: 0,
            PMJMDJEAGAF: 0,
            PININKABAJB: 0,
            id: 0,
            ONDPGANOLJA: 0,
            NFGDGCIPKNE: ::std::vec::Vec::new(),
            CNNEMJIJNEB: 0,
            OCPEDKAHCLO: ::std::vec::Vec::new(),
            BBANNHGDFEF: ::protobuf::MessageField::none(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for NECPIBKAFJE {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("NECPIBKAFJE").unwrap()).clone()
    }
}

impl ::std::fmt::Display for NECPIBKAFJE {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for NECPIBKAFJE {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x11NECPIBKAFJE.proto\x1a\x11LPHBEMJDGKA.proto\"\xbb\x02\n\x0bNECPIBKA\
    FJE\x12\x20\n\x0bLBPJJFNLMFC\x18\x08\x20\x01(\rR\x0bLBPJJFNLMFC\x12\x20\
    \n\x0bPMJMDJEAGAF\x18\t\x20\x01(\x05R\x0bPMJMDJEAGAF\x12\x20\n\x0bPININK\
    ABAJB\x18\x0f\x20\x01(\rR\x0bPININKABAJB\x12\x0e\n\x02id\x18\x0b\x20\x01\
    (\rR\x02id\x12\x20\n\x0bONDPGANOLJA\x18\x0c\x20\x01(\x05R\x0bONDPGANOLJA\
    \x12\x20\n\x0bNFGDGCIPKNE\x18\x02\x20\x03(\rR\x0bNFGDGCIPKNE\x12\x20\n\
    \x0bCNNEMJIJNEB\x18\x03\x20\x01(\rR\x0bCNNEMJIJNEB\x12\x20\n\x0bOCPEDKAH\
    CLO\x18\x05\x20\x03(\rR\x0bOCPEDKAHCLO\x12.\n\x0bBBANNHGDFEF\x18\n\x20\
    \x01(\x0b2\x0c.LPHBEMJDGKAR\x0bBBANNHGDFEFb\x06proto3\
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
            deps.push(super::LPHBEMJDGKA::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(1);
            messages.push(NECPIBKAFJE::generated_message_descriptor_data());
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