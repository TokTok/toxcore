#include <tut/tut.hpp>
#include <tut/tut_reporter.hpp>

#define TEST_GROUP(NAME)		\
namespace tut				\
{					\
typedef test_group<context> factory;	\
typedef factory::object object;		\
}					\
					\
static tut::factory tf(NAME)

#define TEST(N)				\
template<>				\
template<>				\
void tut::object::test<N>()

#define TEST_MAIN							\
int main()								\
{									\
    tut::test_runner &runner = tut::test_runner_singleton::get();	\
    tut::reporter reporter;						\
    runner.set_callback(&reporter);					\
    runner.run_tests();							\
    return 0;								\
}
