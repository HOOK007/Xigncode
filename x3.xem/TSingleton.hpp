#pragma once

#include <memory>

template <class T>
class TSingleton
{
public:
	static T *GetInstance()
	{
		static std::unique_ptr<T> instance(new T);
		return instance.get();
	}

protected:
	TSingleton() = default;

private:
	TSingleton(const TSingleton &) = delete;
	TSingleton& operator=(const TSingleton &) = delete;
	TSingleton(TSingleton &&) = delete;
	TSingleton& operator=(TSingleton &&) = delete;
};