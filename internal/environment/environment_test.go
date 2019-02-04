package environment

import (
	. "gopkg.in/check.v1"

	"os"
	"testing"
)

func Test(t *testing.T) { TestingT(t) }

type ButlerTestSuite struct {
}

var _ = Suite(&ButlerTestSuite{})

/*
func (s *ButlerTestSuite) SetUpSuite(c *C) {
	//ParseConfigFiles(&Files, FileList)
}
*/

func (s *ButlerTestSuite) TestGetVar(c *C) {
	Test1 := GetVar(1)
	c.Assert(Test1, Equals, "1")

	Test2 := GetVar("hi")
	c.Assert(Test2, Equals, "hi")

	Test3 := GetVar("env:DOES_NOT_EXIST")
	c.Assert(Test3, Equals, "")

	os.Setenv("DOES_EXIST", "YES")
	Test4 := GetVar("env:DOES_EXIST")
	c.Assert(Test4, Equals, "YES")
	os.Unsetenv("DOES_EXIST")

	Test5 := GetVar("what what what")
	c.Assert(Test5, Equals, "what what what")

	type Foo struct {
		Bar string
	}
	Test6 := GetVar(Foo{})
	c.Assert(Test6, Equals, "")
}
