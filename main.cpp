#define XSTR(x) STR(x)
#define STR(x) #x
#pragma message "C++ version deduced as: " XSTR(__cplusplus)

#include "md5.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_map>

class File_Engine
{
  public:
    File_Engine(std::istream& file_handle, int block_size = 1)
        : _file(file_handle)
        , _block_size(block_size)
    {
        _data.resize(block_size);
        _file.clear();
        _file.seekg(0, std::ios::beg);
    }

    bool open()
    {
        _file.read((char*) _data.data(), _block_size);

        std::streamsize succesfully_read_bytes = _file.gcount();

        if(succesfully_read_bytes == 0)
        {
            return false;
        }
        else if(succesfully_read_bytes < _block_size)
        {
            _data.resize(succesfully_read_bytes);
        }

        return true;
    }

    void move_cursor(long position_from_start = 0)
    {
        _file.clear();
        _file.seekg(position_from_start, std::ios::beg);

        if(not position_from_start)
        {
            _data.clear();
            _data.resize(_block_size);
        }
    }

    const std::vector<unsigned char>& data()
    {
        return _data;
    }

    size_t get_block_size() const
    {
        return _block_size;
    }

  private:
    std::istream& _file;
    std::vector<unsigned char> _data;
    size_t _block_size = 0;
};

///////////////////////////////////////////////////////////////////

using Block_Index = long;
struct BlockData
{
    std::string strong_signature;
    Block_Index block_index = 0;

    bool operator==(const BlockData& other) const
    {
        return this->strong_signature == other.strong_signature
               && this->block_index == other.block_index;
    }
};

struct Signature
{
    std::unordered_map<Block_Index, BlockData> hash;
    File_Engine& raw_data_provider;
};

///////////////////////////////////////////////////////////////////

class RollingChecksum
{
  public:
    long long calculate(const std::vector<unsigned char>& data)
    {
        _r          = 0;
        _r1         = 0;
        _r2         = 0;
        _block_size = data.size();

        for(int i = 0; i < data.size(); ++i)
        {
            _r1 += data[i];
            _r2 += (_block_size - i) * data[i];
        }

        _r1 = _r1 % module_factor;
        _r2 = _r2 % module_factor;
        _r  = _r1 + module_factor * _r2;

        return _r;
    }

    long long roll(const unsigned char outgoing, const unsigned char incoming)
    {
        _r1 = (_r1 - outgoing + incoming) % module_factor;
        _r2 = (_r2 - _block_size * outgoing + _r1) % module_factor;
        _r  = _r1 + module_factor * _r2;

        return _r;
    }

  public:
    static inline const auto module_factor = 1 << 16;

  private:
    Block_Index _block_size = 0;
    long long _r            = 0;
    long long _r1           = 0;
    long long _r2           = 0;
};

///////////////////////////////////////////////////////////////////

class SignatureCalculator
{
  public:
    SignatureCalculator(File_Engine& data_provider)
        : _file(data_provider)
        , _signature{{}, data_provider}
    {}

    const Signature& calculate()
    {
        Block_Index block_index = 0;
        while(_file.open())
        {
            RollingChecksum r;
            const auto fast_signature = r.calculate(_file.data());
            const auto strong_signature =
                Chocobo1::MD5()
                    .addData(reinterpret_cast<const char*>(_file.data().data()),
                             static_cast<int>(_file.data().size()))
                    .finalize()
                    .toString();

            if(_signature.hash.contains(fast_signature))
            {
                const auto& sign = _signature.hash.at(fast_signature);
                if(sign.strong_signature == strong_signature)
                {
                    ++block_index;
                    continue;
                }

                std::cerr << "Fast signature collision on:\t" << fast_signature << " on data "
                          << _file.data().data() << std::endl;
                std::cerr << "Strong signature does not match | db: " << sign.strong_signature
                          << "\t| strong: " << strong_signature
                          << "\t # fast: " << fast_signature
                          << "\t| data:" << _file.data().data() << std::endl;
            }

            _signature.hash[fast_signature] = {strong_signature, block_index};
            ++block_index;
        }

        _file.move_cursor();

        return _signature;
    }

  private:
    File_Engine& _file;
    Signature _signature;
};

#include "rapidfuzz_amalgamated.hpp"

class DeltaCalculator
{
  public:
    using Modification_Ops = rapidfuzz::EditType;
    struct Delta
    {
        std::string print;
        struct Entry
        {
            ulong from = 0;
            ulong to   = 0;
            std::string reference;
            std::string opposite;
            std::unordered_map<Modification_Ops, ushort> ops;

            bool operator==(const Entry& other) const
            {
                return from == other.from and to == other.to and reference == other.reference
                       and opposite == other.opposite and ops == other.ops;
            }
        };
        std::vector<Entry> entries;
    };

  public:
    DeltaCalculator(File_Engine& data_provider, const Signature& signature)
        : _file(data_provider)
        , _signature(signature)
    {}

    Delta calculate()
    {
        Delta delta;

        if(_signature.hash.empty())
        {
            while(_file.open())
            {
                for(const auto& c : _file.data())
                {
                    delta.print += c;
                }
            }
            return delta;
        }

        delta.print += "____________________________\n"
                       "|                          |\n"
                       "|        Begin Diff        |\n";

        const int block_size                   = _file.get_block_size();
        bool roll_fast_signature_in_next_chunk = false;
        long next_block_start_pos              = 0;
        unsigned char rolled_out_byte          = 0;
        RollingChecksum r;

        const auto accumulate_one_byte_to_slide =
            [&roll_fast_signature_in_next_chunk, &next_block_start_pos, &rolled_out_byte](
                std::string& block_delta, unsigned char byte)
        {
            block_delta += byte;
            rolled_out_byte = byte;
            ++next_block_start_pos;
            roll_fast_signature_in_next_chunk = true;
        };

        Block_Index file_block_index = 0;
        std::string block_print;
        ulong block_start_position = 0;
        ulong block_end_position   = 0;
        while(_file.open())
        {
            const auto& buffer = _file.data();
            if(buffer.size() < block_size)
            {
                roll_fast_signature_in_next_chunk = false;
            }

            long long fast_signature = roll_fast_signature_in_next_chunk
                                           ? r.roll(rolled_out_byte, buffer[buffer.size() - 1])
                                           : r.calculate(buffer);

            bool diffed = false;
            if(_signature.hash.contains(fast_signature))
            {
                const auto& sign = _signature.hash.at(fast_signature);
                const std::string strong_signature =
                    Chocobo1::MD5()
                        .addData(reinterpret_cast<const char*>(buffer.data()),
                                 static_cast<int>(buffer.size()))
                        .finalize()
                        .toString();

                if(sign.strong_signature == strong_signature)
                {
                    // changes ended
                    if(not block_print.empty())
                    {
                        diffed = true;
                    }
                    else
                    {
                        block_start_position = next_block_start_pos - 1;
                        block_start_position += buffer.size();
                    }

                    block_end_position = next_block_start_pos;
                    next_block_start_pos += buffer.size();
                    roll_fast_signature_in_next_chunk = false;
                }
                else
                {
                    //corner case
                    accumulate_one_byte_to_slide(block_print, buffer[0]);
                }
            }
            else
            {
                // change, keep memorizing
                accumulate_one_byte_to_slide(block_print, buffer[0]);
            }

            if(diffed)
            {
                const auto block_order = (block_end_position / _file.get_block_size());
                delta.print +=
                    "|__________________________|\nFile block:" + std::to_string(block_order)
                    + " (" + std::to_string(block_start_position) + "-"
                    + std::to_string(block_end_position) + ") \t "
                    + "\n||||||||||||||||||||||||||||\n";

                const auto cross_file_cursor = block_start_position;
                std::string cross_raw_text = align_cross_diff(block_print, cross_file_cursor);
                const auto mod_ops =
                    get_levenshtein_distance_ops_report(block_print, cross_raw_text);
                const std::string mod_ops_report =
                    "+" + std::to_string(mod_ops.at(rapidfuzz::EditType::Insert)) + " -"
                    + std::to_string(mod_ops.at(rapidfuzz::EditType::Delete)) + " ~"
                    + std::to_string(mod_ops.at(rapidfuzz::EditType::Replace));

                delta.print += block_print + "\n||||||||| " + mod_ops_report + " |||||||||\n";
                delta.print += cross_raw_text;
                delta.print +=
                    "\n||||||||||||||||||||||||||||\n____________________________\n|     "
                    "                     |\n|      Same So Far...      |\n";

                delta.entries.push_back({block_start_position,
                                         block_end_position,
                                         block_print,
                                         cross_raw_text,
                                         mod_ops});

                block_start_position = block_end_position;
                block_print.clear();
                diffed = false;
            }

            ++file_block_index;

            _file.move_cursor(next_block_start_pos);
        }

        delta.print.resize(delta.print.size() - 29);
        delta.print += "|            Bye           |\n";
        delta.print += "|__________________________|";
        return delta;
    }

  private:
    std::string align_cross_diff(const std::string& block_print, const long cross_file_cursor)
    {
        std::string cross_raw_text;
        _signature.raw_data_provider.move_cursor(cross_file_cursor);
        if(_signature.raw_data_provider.open())
        {
            cross_raw_text = std::string((char*) _signature.raw_data_provider.data().data(),
                                         _signature.raw_data_provider.data().size());

            bool stretched = false;
            while((cross_raw_text.length()+(int)(_signature.raw_data_provider.get_block_size()/2)) < block_print.length())
            {
                _signature.raw_data_provider.open();
                cross_raw_text +=
                    std::string((char*) _signature.raw_data_provider.data().data(),
                                _signature.raw_data_provider.data().size());
                stretched = true;
            }
            if(stretched)
            {
                cross_raw_text.resize(block_print.length());
            }
            if(cross_file_cursor == 0)
            {
                return cross_raw_text;
            }

            const auto shift_amount = find_shift_of_diffed_blocks(block_print, cross_raw_text);

            if(shift_amount not_eq 0)
            {
                _signature.raw_data_provider.move_cursor(cross_file_cursor - shift_amount);
                if(_signature.raw_data_provider.open())
                {
                    cross_raw_text =
                        std::string((char*) _signature.raw_data_provider.data().data(),
                                    _signature.raw_data_provider.data().size());

                    if(stretched)
                    {
                        while(cross_raw_text.length()<block_print.length())
                        {
                            _signature.raw_data_provider.open();
                            cross_raw_text += std::string((char*) _signature.raw_data_provider.data().data(),
                                                          _signature.raw_data_provider.data().size());
                        }
                        fit_end_of_cross_after_left_alignment(block_print,cross_raw_text);
                    }
                }
            }

            _signature.raw_data_provider.move_cursor();
        }

        return cross_raw_text;
    }

    void fit_end_of_cross_after_left_alignment(const std::string& ref, std::string& cross,const double overlap_percent = 0.1)
    {
        unsigned int overlap_num_chars            = cross.length() * overlap_percent;
        std::basic_string<char>::size_type cursor = 0;
        int32_t matching_point                    = -1;
        uint32_t occurrences                      = std::numeric_limits<uint32_t>::max();

        for(; (occurrences > 1 or occurrences == 0)
              and matching_point < (int32_t) (cross.length() - overlap_num_chars);)
        {
            ++matching_point;
            occurrences       = 0;
            overlap_num_chars = std::max((size_t) 3, (size_t) ((ref.length() - matching_point) * overlap_percent));
            const std::string target_part = ref.substr(ref.length()-matching_point-overlap_num_chars, overlap_num_chars);

            while((cursor = cross.find(target_part, cursor)) not_eq std::string::npos)
            {
                ++occurrences;
                cursor += overlap_num_chars;
            }
            cursor = 0;
        }
        cursor =
            cross.find(ref.substr(ref.length()-matching_point-overlap_num_chars, overlap_num_chars), cursor) - matching_point;
        cross.resize(cursor+overlap_num_chars);
    }

    int find_shift_of_diffed_blocks(const std::string& ref,
                                    const std::string& cross,
                                    const double overlap_percent = 0.1)
    {
        // std::cout << ref << "\n|||||||||||||||||||||||||||\n" << cross;
        // std::cout << "\n|||||||||||||||||||||||||||\n" << std::endl << std::endl;

        unsigned int overlap_num_chars            = cross.length() * overlap_percent;
        std::basic_string<char>::size_type cursor = 0;
        int32_t matching_point                    = -1;
        uint32_t occurrences                      = std::numeric_limits<uint32_t>::max();

        for(; (occurrences > 1 or occurrences == 0)
              and matching_point < (int32_t) (cross.length() - overlap_num_chars);)
        {
            ++matching_point;
            occurrences       = 0;
            overlap_num_chars = std::max(
                (size_t) 3, (size_t) ((cross.length() - matching_point) * overlap_percent));
            const std::string target_part = cross.substr(matching_point, overlap_num_chars);
            while((cursor = ref.find(target_part, cursor)) not_eq std::string::npos)
            {
                ++occurrences;
                cursor += overlap_num_chars;
            }
            cursor = 0;
        }
        cursor =
            ref.find(cross.substr(matching_point, overlap_num_chars), cursor) - matching_point;
        const auto shift = occurrences == 1 ? cursor : 0;
        return shift;
    }

  private:
    std::unordered_map<Modification_Ops, ushort> get_levenshtein_distance_ops_report(
        const std::string& ref,
        const std::string& opposite)
    {
        const auto& levenshtein_difference = rapidfuzz::levenshtein_editops(ref, opposite);
        ushort additions = 0, removals = 0, replacements = 0;
        for(const auto& ops : levenshtein_difference)
        {
            if(ops.type == rapidfuzz::EditType::Insert)
            {
                ++additions;
            }
            else if(ops.type == rapidfuzz::EditType::Delete)
            {
                ++removals;
            }
            else if(ops.type == rapidfuzz::EditType::Replace)
            {
                ++replacements;
            }
        }

        return {{rapidfuzz::EditType::Insert, additions},
                {rapidfuzz::EditType::Delete, removals},
                {rapidfuzz::EditType::Replace, replacements}};
    }

  private:
    File_Engine& _file;
    const Signature _signature;
};

bool test(const unsigned int block_size = 32, bool print = false);

int
main(int argc, char** argv)
{
    if(argc < 3)
    {
        std::cout
            << "You had not give two file paths to compare, so I will run test using my data."
            << std::endl
            << std::endl;
    }

    const unsigned int block_size = 32;

    if(block_size < std::log2(RollingChecksum::module_factor))
    {
        std::cerr << "Incorrect block size used! Must be greater than rolling modulo\t"
                  << RollingChecksum::module_factor << std::endl;
        return -1;
    }

    if(not test(block_size, argc < 3))
    {
        std::cerr
            << "Test did not pass and it is boring to tell you exactly something wrong...\n";
        return 128;
    }

    if(argc < 3)
    {
        return 0;
    }

    const std::string first_file_name  = argv[1];
    const std::string second_file_name = argv[2];

    std::ifstream first_file_handle(first_file_name, std::ios::binary);
    std::ifstream second_file_handle(second_file_name, std::ios::binary);
    if(!first_file_handle)
    {
        std::cerr << "Cannot open the file : " << first_file_name << '\n';
        return -1;
    }

    if(!second_file_handle)
    {
        std::cerr << "Cannot open the file : " << second_file_name << '\n';
        return -1;
    }

    File_Engine first_file(first_file_handle, block_size);
    File_Engine second_file(second_file_handle, block_size);

    SignatureCalculator second_signature_calculator{second_file};
    const auto& second_signature = second_signature_calculator.calculate();

    first_file.move_cursor();
    second_file.move_cursor();

    std::cout << "Second Signature: " << second_signature.hash.size() << " blocks"
              << std::endl;

    DeltaCalculator first_delta_calculator{first_file, second_signature};
    DeltaCalculator::Delta first_delta = first_delta_calculator.calculate();
    std::cout << "### Delta ###" << std::endl << first_delta.print << std::endl;


    return 0;
}

#include "test_material.hpp"

bool
test(const unsigned int block_size, bool print)
{
    if(print)
    {
        std::cout
            << "-------------------------------------------------------------------------\n";
        std::cout << "### Reference ###" << std::endl;
        std::cout
            << "-------------------------------------------------------------------------\n";
        std::cout << test_reference_input << std::endl;
        std::cout << std::endl << std::endl;
        std::cout
            << "-------------------------------------------------------------------------\n#"
               "## Modified ###"
            << std::endl;
        std::cout
            << "-------------------------------------------------------------------------\n";
        std::cout << test_mod_input << std::endl;
        std::cout << std::endl << std::endl;
    }

    std::istringstream ref_file{test_reference_input};
    std::istringstream mod_file{test_mod_input};

    File_Engine first_file(ref_file, block_size);
    File_Engine second_file(mod_file, block_size);

    SignatureCalculator second_signature_calculator{second_file};
    const auto& second_signature = second_signature_calculator.calculate();
    second_file.move_cursor();
    if(print)
    {
        std::cout
            << "-------------------------------------------------------------------------\n";
        std::cout << "Signature: " << second_signature.hash.size() << " blocks" << std::endl;
    }

    DeltaCalculator first_delta_calculator{first_file, second_signature};
    DeltaCalculator::Delta first_delta = first_delta_calculator.calculate();

    std::vector<DeltaCalculator::Delta::Entry> right_answer;
    right_answer.push_back({0,
                            31,
                            "Rolling Hash Algorithm\n    _Spe",
                            "aRolling Hash Algorithm\n    _Spe",
                            {{rapidfuzz::EditType::Insert, 1},
                             {rapidfuzz::EditType::Delete, 0},
                             {rapidfuzz::EditType::Replace, 0}}});
    right_answer.push_back({862,
                            928,
                            "\n    ## Requirements\n    - Hashing function gets the data as a pa",
                            "\n    ## Requirements\n    - Bashing function gets the dat as a pa",
                            {{rapidfuzz::EditType::Insert, 0},
                             {rapidfuzz::EditType::Delete, 1},
                             {rapidfuzz::EditType::Replace, 1}}});
    right_answer.push_back({1247,
                            1279,
                            "nction well in describing the o",
                            "nction welll in describing the o",
                            {{rapidfuzz::EditType::Insert, 1},
                             {rapidfuzz::EditType::Delete, 0},
                             {rapidfuzz::EditType::Replace, 0}}});

    const bool passed = first_delta.entries == right_answer;
    if(print)
    {
        std::cout << "### Delta ###" << std::endl << first_delta.print << std::endl;
    }
    std::cout << "-------------------------------------------------------------------------\n";
    std::cout << "Test " << (passed ? "passed" : "failed") << std::endl;
    std::cout << "-------------------------------------------------------------------------\n";
    std::cout << std::endl << std::endl << std::endl;

    return passed;
}
