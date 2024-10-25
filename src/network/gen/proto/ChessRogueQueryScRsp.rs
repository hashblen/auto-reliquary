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

//! Generated file from `ChessRogueQueryScRsp.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_4_0;

// @@protoc_insertion_point(message:ChessRogueQueryScRsp)
#[derive(PartialEq,Clone,Default,Debug)]
pub struct ChessRogueQueryScRsp {
    // message fields
    // @@protoc_insertion_point(field:ChessRogueQueryScRsp.CBLEOKIPEEA)
    pub CBLEOKIPEEA: ::protobuf::MessageField<super::LCGKENFJICO::LCGKENFJICO>,
    // @@protoc_insertion_point(field:ChessRogueQueryScRsp.JMGAILLNCEL)
    pub JMGAILLNCEL: ::protobuf::MessageField<super::KFDJPCGIBEH::KFDJPCGIBEH>,
    // @@protoc_insertion_point(field:ChessRogueQueryScRsp.ROGUE_DEBUG_MESSAGE_TYPE_INFO)
    pub ROGUE_DEBUG_MESSAGE_TYPE_INFO: ::protobuf::MessageField<super::NLGOGJBLJFE::NLGOGJBLJFE>,
    // @@protoc_insertion_point(field:ChessRogueQueryScRsp.CMPAKCFPGJN)
    pub CMPAKCFPGJN: ::protobuf::MessageField<super::JHPFGKKNOGF::JHPFGKKNOGF>,
    // @@protoc_insertion_point(field:ChessRogueQueryScRsp.CMDGDKBACOD)
    pub CMDGDKBACOD: ::protobuf::MessageField<super::EOIFAHBJKDA::EOIFAHBJKDA>,
    // @@protoc_insertion_point(field:ChessRogueQueryScRsp.retcode)
    pub retcode: u32,
    // special fields
    // @@protoc_insertion_point(special_field:ChessRogueQueryScRsp.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a ChessRogueQueryScRsp {
    fn default() -> &'a ChessRogueQueryScRsp {
        <ChessRogueQueryScRsp as ::protobuf::Message>::default_instance()
    }
}

impl ChessRogueQueryScRsp {
    pub fn new() -> ChessRogueQueryScRsp {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(6);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::LCGKENFJICO::LCGKENFJICO>(
            "CBLEOKIPEEA",
            |m: &ChessRogueQueryScRsp| { &m.CBLEOKIPEEA },
            |m: &mut ChessRogueQueryScRsp| { &mut m.CBLEOKIPEEA },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::KFDJPCGIBEH::KFDJPCGIBEH>(
            "JMGAILLNCEL",
            |m: &ChessRogueQueryScRsp| { &m.JMGAILLNCEL },
            |m: &mut ChessRogueQueryScRsp| { &mut m.JMGAILLNCEL },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::NLGOGJBLJFE::NLGOGJBLJFE>(
            "ROGUE_DEBUG_MESSAGE_TYPE_INFO",
            |m: &ChessRogueQueryScRsp| { &m.ROGUE_DEBUG_MESSAGE_TYPE_INFO },
            |m: &mut ChessRogueQueryScRsp| { &mut m.ROGUE_DEBUG_MESSAGE_TYPE_INFO },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::JHPFGKKNOGF::JHPFGKKNOGF>(
            "CMPAKCFPGJN",
            |m: &ChessRogueQueryScRsp| { &m.CMPAKCFPGJN },
            |m: &mut ChessRogueQueryScRsp| { &mut m.CMPAKCFPGJN },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::EOIFAHBJKDA::EOIFAHBJKDA>(
            "CMDGDKBACOD",
            |m: &ChessRogueQueryScRsp| { &m.CMDGDKBACOD },
            |m: &mut ChessRogueQueryScRsp| { &mut m.CMDGDKBACOD },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "retcode",
            |m: &ChessRogueQueryScRsp| { &m.retcode },
            |m: &mut ChessRogueQueryScRsp| { &mut m.retcode },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<ChessRogueQueryScRsp>(
            "ChessRogueQueryScRsp",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for ChessRogueQueryScRsp {
    const NAME: &'static str = "ChessRogueQueryScRsp";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                90 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.CBLEOKIPEEA)?;
                },
                74 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.JMGAILLNCEL)?;
                },
                98 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.ROGUE_DEBUG_MESSAGE_TYPE_INFO)?;
                },
                58 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.CMPAKCFPGJN)?;
                },
                10 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.CMDGDKBACOD)?;
                },
                120 => {
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
        if let Some(v) = self.CBLEOKIPEEA.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if let Some(v) = self.JMGAILLNCEL.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if let Some(v) = self.ROGUE_DEBUG_MESSAGE_TYPE_INFO.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if let Some(v) = self.CMPAKCFPGJN.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if let Some(v) = self.CMDGDKBACOD.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if self.retcode != 0 {
            my_size += ::protobuf::rt::uint32_size(15, self.retcode);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.CBLEOKIPEEA.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(11, v, os)?;
        }
        if let Some(v) = self.JMGAILLNCEL.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(9, v, os)?;
        }
        if let Some(v) = self.ROGUE_DEBUG_MESSAGE_TYPE_INFO.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(12, v, os)?;
        }
        if let Some(v) = self.CMPAKCFPGJN.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(7, v, os)?;
        }
        if let Some(v) = self.CMDGDKBACOD.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
        }
        if self.retcode != 0 {
            os.write_uint32(15, self.retcode)?;
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

    fn new() -> ChessRogueQueryScRsp {
        ChessRogueQueryScRsp::new()
    }

    fn clear(&mut self) {
        self.CBLEOKIPEEA.clear();
        self.JMGAILLNCEL.clear();
        self.ROGUE_DEBUG_MESSAGE_TYPE_INFO.clear();
        self.CMPAKCFPGJN.clear();
        self.CMDGDKBACOD.clear();
        self.retcode = 0;
        self.special_fields.clear();
    }

    fn default_instance() -> &'static ChessRogueQueryScRsp {
        static instance: ChessRogueQueryScRsp = ChessRogueQueryScRsp {
            CBLEOKIPEEA: ::protobuf::MessageField::none(),
            JMGAILLNCEL: ::protobuf::MessageField::none(),
            ROGUE_DEBUG_MESSAGE_TYPE_INFO: ::protobuf::MessageField::none(),
            CMPAKCFPGJN: ::protobuf::MessageField::none(),
            CMDGDKBACOD: ::protobuf::MessageField::none(),
            retcode: 0,
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for ChessRogueQueryScRsp {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("ChessRogueQueryScRsp").unwrap()).clone()
    }
}

impl ::std::fmt::Display for ChessRogueQueryScRsp {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ChessRogueQueryScRsp {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x1aChessRogueQueryScRsp.proto\x1a\x11EOIFAHBJKDA.proto\x1a\x11JHPFGKK\
    NOGF.proto\x1a\x11KFDJPCGIBEH.proto\x1a\x11LCGKENFJICO.proto\x1a\x11NLGO\
    GJBLJFE.proto\"\xc0\x02\n\x14ChessRogueQueryScRsp\x12.\n\x0bCBLEOKIPEEA\
    \x18\x0b\x20\x01(\x0b2\x0c.LCGKENFJICOR\x0bCBLEOKIPEEA\x12.\n\x0bJMGAILL\
    NCEL\x18\t\x20\x01(\x0b2\x0c.KFDJPCGIBEHR\x0bJMGAILLNCEL\x12N\n\x1dROGUE\
    _DEBUG_MESSAGE_TYPE_INFO\x18\x0c\x20\x01(\x0b2\x0c.NLGOGJBLJFER\x19ROGUE\
    DEBUGMESSAGETYPEINFO\x12.\n\x0bCMPAKCFPGJN\x18\x07\x20\x01(\x0b2\x0c.JHP\
    FGKKNOGFR\x0bCMPAKCFPGJN\x12.\n\x0bCMDGDKBACOD\x18\x01\x20\x01(\x0b2\x0c\
    .EOIFAHBJKDAR\x0bCMDGDKBACOD\x12\x18\n\x07retcode\x18\x0f\x20\x01(\rR\
    \x07retcodeb\x06proto3\
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
            let mut deps = ::std::vec::Vec::with_capacity(5);
            deps.push(super::EOIFAHBJKDA::file_descriptor().clone());
            deps.push(super::JHPFGKKNOGF::file_descriptor().clone());
            deps.push(super::KFDJPCGIBEH::file_descriptor().clone());
            deps.push(super::LCGKENFJICO::file_descriptor().clone());
            deps.push(super::NLGOGJBLJFE::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(1);
            messages.push(ChessRogueQueryScRsp::generated_message_descriptor_data());
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