#pragma once

#include <string>

namespace std {
    namespace win32 {
        class registry {
        public:
            ~registry();
            static registry class_root(const char* path);
            static registry current_user(const char* path);
            static registry local_machine(const char* path);
            bool get_value(const char* key, string& val);
            //bool get_value(const char* key, int& val);
        private:
            registry(void* root, const char* path);
            bool m_isvalid;
            void* m_key;
        };
    }
}