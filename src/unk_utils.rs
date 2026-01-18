use std::collections::HashMap;
use protobuf::Message;
use protobuf::UnknownValueRef::*;
use crate::gen::protos::Unk;

pub fn matches_player_get_token_sc_rsp(data: Vec<u8>) -> Option<u64> {
    let d_msg = Unk::parse_from_bytes(&data);
    match d_msg {
        Ok(d_msg) => {
            let mut possible_seeds: Vec<u64> = vec![];
            let unknown_fields = d_msg.unknown_fields();
            for (_, field_data) in unknown_fields.iter() {
                if let Varint(seed) = field_data {
                    if seed > 1 << 32 {
                        possible_seeds.push(seed)
                    }
                };
            }
            if possible_seeds.len() == 1 {
                Some(possible_seeds[0])
            }
            else { None }
        }
        _ => None
    }
}

#[derive(Default)]
pub struct Achievement {
    pub id: u32,
    pub status: u32,
    pub finish_timestamp: Option<u32>
}

pub fn matches_get_quest_data_sc_rsp(data: Vec<u8>) -> Option<Vec<Achievement>> {
    if data.len() < 1000 {
        return None
    }
    let d_msg = Unk::parse_from_bytes(&data);
    match d_msg {
        Ok(d_msg) => {
            let mut achievement_list: Vec<HashMap<u32, u64>> = vec![];
            let mut list_tag: Option<u32> = None;
            let unknown_fields = d_msg.unknown_fields();
            // let tags = unknown_fields.iter().map(|(tag, _)| tag).collect::<HashSet<u32>>();
            // if tags.len() != 2 { return None }
            for (field_number, field_data) in unknown_fields.iter() {
                match field_data {
                    LengthDelimited(bytes) => {
                        let d_msg_inside = Unk::parse_from_bytes(bytes);
                        let unknown_fields_inside;
                        match d_msg_inside {
                            Ok(d_msg_inside) => {
                                unknown_fields_inside = d_msg_inside.unknown_fields().clone()
                            }
                            _ => continue
                        }
                        if unknown_fields_inside.iter().count() > 5 { return None }
                        let mut achievement_map: HashMap<u32, u64> = HashMap::new();
                        for(field_number_inside, field_data_inside) in unknown_fields_inside.iter() {
                            if let Varint(value) = field_data_inside {
                                let _ = achievement_map.insert(field_number_inside, value);
                            }
                        }
                        achievement_list.push(achievement_map);
                        match list_tag {
                            Some(x) => {
                                if field_number != x { return None }  // if we found several possible tags for the list. Not possible.
                            }
                            None => list_tag = Some(field_number)
                        }
                    }
                    _ => ()
                }
            }
            if achievement_list.len() == 0 { return None }

            // Now, try to find which field corresponds to the right places
            let mut tag_finish_timestamp = None;
            let mut tag_id = None;
            let mut possible_tag_status: Vec<u32> = achievement_list[0].clone().into_keys().collect();
            for achievement_map in &achievement_list {
                for (&tag, &value) in achievement_map.iter() {
                    if value > 1420066800 {  // Wed Dec 31 2014 23:00:00 GMT+0000
                        tag_finish_timestamp = match tag_finish_timestamp {
                            Some(t) => {
                                if t != tag { return None }
                                else { tag_finish_timestamp }
                            }
                            _ => Some(tag)
                        }
                    }
                    if value == 4040201 {  // Until the Light Takes Us: Activate 5 Space Anchors in the Herta Space Station
                        tag_id = Some(tag)
                    }
                    if possible_tag_status.contains(&tag) {
                        if value > 4 {
                            possible_tag_status.retain(|&x| x != tag)
                        }
                    }
                }
            }

            if tag_finish_timestamp == None || tag_id == None || possible_tag_status.len() == 0 {
                return None
            }

            // Finally, collect the Achievements
            let tag_status = possible_tag_status[0];
            let mut achievements: Vec<Achievement> = vec![];
            for achievement_map in &achievement_list {
                let mut achievement = Achievement {..Default::default()};
                for (&tag, &value) in achievement_map.iter() {
                    if tag_finish_timestamp.unwrap() == tag {
                        achievement.finish_timestamp = Some(value as u32);
                    }
                    if tag_id.unwrap() == tag {
                        achievement.id = value as u32;
                    }
                    if tag_status == tag {
                        achievement.status = value as u32;
                    }
                }
                achievements.push(achievement)
            }
            assert!(achievements.len() > 0);
            Some(achievements)
        }
        _ => None
    }
}