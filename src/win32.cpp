#include <ext/win32.hpp>

#include <Windows.h>
#include <Shlwapi.h>
#pragma comment(lib,"Shlwapi.lib")

namespace std {
    namespace win32 {
        registry registry::current_user(const char * path)
        {
            return registry(HKEY_CURRENT_USER, path);
        }
        registry registry::local_machine(const char * path)
        {
            return registry(HKEY_LOCAL_MACHINE, path);
        }
        registry::registry(void* root, const char* path) : m_isvalid(false), m_key(nullptr)
        {
            LSTATUS Ret = RegOpenKeyExA((HKEY)root, path, 0, KEY_QUERY_VALUE, (PHKEY)&m_key);
            m_isvalid = Ret == ERROR_SUCCESS;
        }
        registry registry::class_root(const char * path)
        {
            return registry(HKEY_CLASSES_ROOT, path);
        }
        registry::~registry()
        {
            if (m_isvalid)
            {
                RegCloseKey((HKEY)m_key);
            }
        }
        bool registry::is_valid() const
        {
            return m_isvalid;
        }
        bool registry::get_value(const char * key, string & val)
        {
            if(!m_isvalid)
                return false;
            DWORD length = 0;
            LSTATUS Ret = RegQueryValueExA((HKEY)m_key, key, NULL, NULL, NULL, &length);
            if (Ret != ERROR_SUCCESS)
                return false;
            val.resize(length + 1, '\0');
            return RegQueryValueExA((HKEY)m_key, key, NULL, NULL, (LPBYTE)val.data(), &length) == ERROR_SUCCESS;
        }
        string _path_combine(const string& p0, const string& p1)
        {
            char pathbuffer[1024] = { 0 };
            auto ret = PathCombineA(pathbuffer, p0.c_str(), p1.c_str());
            return ret ? ret : "";
        }
        bool _path_exist(const string& p) {
            return PathFileExistsA(p.c_str()) == TRUE;
        }
    }
}