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

//! Generated file from `GetSwordTrainingDataScRsp.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

// @@protoc_insertion_point(message:GetSwordTrainingDataScRsp)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct GetSwordTrainingDataScRsp {
    // message fields
    // @@protoc_insertion_point(field:GetSwordTrainingDataScRsp.BEDINILDMEB)
    pub BEDINILDMEB: ::protobuf::MessageField<super::HPPHNMBHEEJ::HPPHNMBHEEJ>,
    // @@protoc_insertion_point(field:GetSwordTrainingDataScRsp.CJIKOHPNNMP)
    pub CJIKOHPNNMP: ::std::vec::Vec<u32>,
    // @@protoc_insertion_point(field:GetSwordTrainingDataScRsp.OJFJFEJMJPG)
    pub OJFJFEJMJPG: ::protobuf::MessageField<super::NOMJFEEALFA::NOMJFEEALFA>,
    // @@protoc_insertion_point(field:GetSwordTrainingDataScRsp.OFMIAGOIPJM)
    pub OFMIAGOIPJM: ::std::vec::Vec<u32>,
    // @@protoc_insertion_point(field:GetSwordTrainingDataScRsp.PJEADDDAGKK)
    pub PJEADDDAGKK: u32,
    // @@protoc_insertion_point(field:GetSwordTrainingDataScRsp.JFOJHGPHAHF)
    pub JFOJHGPHAHF: bool,
    // @@protoc_insertion_point(field:GetSwordTrainingDataScRsp.PNIBCBABNLC)
    pub PNIBCBABNLC: ::std::vec::Vec<u32>,
    // @@protoc_insertion_point(field:GetSwordTrainingDataScRsp.retcode)
    pub retcode: u32,
    // special fields
    // @@protoc_insertion_point(special_field:GetSwordTrainingDataScRsp.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a GetSwordTrainingDataScRsp {
    fn default() -> &'a GetSwordTrainingDataScRsp {
        <GetSwordTrainingDataScRsp as ::protobuf::Message>::default_instance()
    }
}

impl GetSwordTrainingDataScRsp {
    pub fn new() -> GetSwordTrainingDataScRsp {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(8);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::HPPHNMBHEEJ::HPPHNMBHEEJ>(
            "BEDINILDMEB",
            |m: &GetSwordTrainingDataScRsp| { &m.BEDINILDMEB },
            |m: &mut GetSwordTrainingDataScRsp| { &mut m.BEDINILDMEB },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "CJIKOHPNNMP",
            |m: &GetSwordTrainingDataScRsp| { &m.CJIKOHPNNMP },
            |m: &mut GetSwordTrainingDataScRsp| { &mut m.CJIKOHPNNMP },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::NOMJFEEALFA::NOMJFEEALFA>(
            "OJFJFEJMJPG",
            |m: &GetSwordTrainingDataScRsp| { &m.OJFJFEJMJPG },
            |m: &mut GetSwordTrainingDataScRsp| { &mut m.OJFJFEJMJPG },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "OFMIAGOIPJM",
            |m: &GetSwordTrainingDataScRsp| { &m.OFMIAGOIPJM },
            |m: &mut GetSwordTrainingDataScRsp| { &mut m.OFMIAGOIPJM },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "PJEADDDAGKK",
            |m: &GetSwordTrainingDataScRsp| { &m.PJEADDDAGKK },
            |m: &mut GetSwordTrainingDataScRsp| { &mut m.PJEADDDAGKK },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "JFOJHGPHAHF",
            |m: &GetSwordTrainingDataScRsp| { &m.JFOJHGPHAHF },
            |m: &mut GetSwordTrainingDataScRsp| { &mut m.JFOJHGPHAHF },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "PNIBCBABNLC",
            |m: &GetSwordTrainingDataScRsp| { &m.PNIBCBABNLC },
            |m: &mut GetSwordTrainingDataScRsp| { &mut m.PNIBCBABNLC },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "retcode",
            |m: &GetSwordTrainingDataScRsp| { &m.retcode },
            |m: &mut GetSwordTrainingDataScRsp| { &mut m.retcode },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<GetSwordTrainingDataScRsp>(
            "GetSwordTrainingDataScRsp",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for GetSwordTrainingDataScRsp {
    const NAME: &'static str = "GetSwordTrainingDataScRsp";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.BEDINILDMEB)?;
                },
                34 => {
                    is.read_repeated_packed_uint32_into(&mut self.CJIKOHPNNMP)?;
                },
                32 => {
                    self.CJIKOHPNNMP.push(is.read_uint32()?);
                },
                26 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.OJFJFEJMJPG)?;
                },
                66 => {
                    is.read_repeated_packed_uint32_into(&mut self.OFMIAGOIPJM)?;
                },
                64 => {
                    self.OFMIAGOIPJM.push(is.read_uint32()?);
                },
                80 => {
                    self.PJEADDDAGKK = is.read_uint32()?;
                },
                16 => {
                    self.JFOJHGPHAHF = is.read_bool()?;
                },
                50 => {
                    is.read_repeated_packed_uint32_into(&mut self.PNIBCBABNLC)?;
                },
                48 => {
                    self.PNIBCBABNLC.push(is.read_uint32()?);
                },
                96 => {
                    self.retcode = is.read_uint32()?;
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
        if let Some(v) = self.BEDINILDMEB.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        for value in &self.CJIKOHPNNMP {
            my_size += ::protobuf::rt::uint32_size(4, *value);
        };
        if let Some(v) = self.OJFJFEJMJPG.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        for value in &self.OFMIAGOIPJM {
            my_size += ::protobuf::rt::uint32_size(8, *value);
        };
        if self.PJEADDDAGKK != 0 {
            my_size += ::protobuf::rt::uint32_size(10, self.PJEADDDAGKK);
        }
        if self.JFOJHGPHAHF != false {
            my_size += 1 + 1;
        }
        for value in &self.PNIBCBABNLC {
            my_size += ::protobuf::rt::uint32_size(6, *value);
        };
        if self.retcode != 0 {
            my_size += ::protobuf::rt::uint32_size(12, self.retcode);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.BEDINILDMEB.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
        }
        for v in &self.CJIKOHPNNMP {
            os.write_uint32(4, *v)?;
        };
        if let Some(v) = self.OJFJFEJMJPG.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(3, v, os)?;
        }
        for v in &self.OFMIAGOIPJM {
            os.write_uint32(8, *v)?;
        };
        if self.PJEADDDAGKK != 0 {
            os.write_uint32(10, self.PJEADDDAGKK)?;
        }
        if self.JFOJHGPHAHF != false {
            os.write_bool(2, self.JFOJHGPHAHF)?;
        }
        for v in &self.PNIBCBABNLC {
            os.write_uint32(6, *v)?;
        };
        if self.retcode != 0 {
            os.write_uint32(12, self.retcode)?;
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

    fn new() -> GetSwordTrainingDataScRsp {
        GetSwordTrainingDataScRsp::new()
    }

    fn clear(&mut self) {
        self.BEDINILDMEB.clear();
        self.CJIKOHPNNMP.clear();
        self.OJFJFEJMJPG.clear();
        self.OFMIAGOIPJM.clear();
        self.PJEADDDAGKK = 0;
        self.JFOJHGPHAHF = false;
        self.PNIBCBABNLC.clear();
        self.retcode = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static GetSwordTrainingDataScRsp {
        static instance: GetSwordTrainingDataScRsp = GetSwordTrainingDataScRsp {
            BEDINILDMEB: ::protobuf::MessageField::none(),
            CJIKOHPNNMP: ::std::vec::Vec::new(),
            OJFJFEJMJPG: ::protobuf::MessageField::none(),
            OFMIAGOIPJM: ::std::vec::Vec::new(),
            PJEADDDAGKK: 0,
            JFOJHGPHAHF: false,
            PNIBCBABNLC: ::std::vec::Vec::new(),
            retcode: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for GetSwordTrainingDataScRsp {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("GetSwordTrainingDataScRsp").unwrap()).clone()
    }
}

impl ::std::fmt::Display for GetSwordTrainingDataScRsp {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for GetSwordTrainingDataScRsp {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x1fGetSwordTrainingDataScRsp.proto\x1a\x11HPPHNMBHEEJ.proto\x1a\x11NO\
    MJFEEALFA.proto\"\xbf\x02\n\x19GetSwordTrainingDataScRsp\x12.\n\x0bBEDIN\
    ILDMEB\x18\x01\x20\x01(\x0b2\x0c.HPPHNMBHEEJR\x0bBEDINILDMEB\x12\x20\n\
    \x0bCJIKOHPNNMP\x18\x04\x20\x03(\rR\x0bCJIKOHPNNMP\x12.\n\x0bOJFJFEJMJPG\
    \x18\x03\x20\x01(\x0b2\x0c.NOMJFEEALFAR\x0bOJFJFEJMJPG\x12\x20\n\x0bOFMI\
    AGOIPJM\x18\x08\x20\x03(\rR\x0bOFMIAGOIPJM\x12\x20\n\x0bPJEADDDAGKK\x18\
    \n\x20\x01(\rR\x0bPJEADDDAGKK\x12\x20\n\x0bJFOJHGPHAHF\x18\x02\x20\x01(\
    \x08R\x0bJFOJHGPHAHF\x12\x20\n\x0bPNIBCBABNLC\x18\x06\x20\x03(\rR\x0bPNI\
    BCBABNLC\x12\x18\n\x07retcode\x18\x0c\x20\x01(\rR\x07retcodeb\x06proto3\
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
            let mut deps = ::std::vec::Vec::with_capacity(2);
            deps.push(super::HPPHNMBHEEJ::file_descriptor().clone());
            deps.push(super::NOMJFEEALFA::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(1);
            messages.push(GetSwordTrainingDataScRsp::generated_message_descriptor_data());
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