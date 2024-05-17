'use strict';

var chai = require('chai');
var should = chai.should();
var passwordHelper = require('../../model/password_with_bug');

describe('Password Helper', function() {
  describe('#hash() - password hashing', function() {
    it('should return a knwon hash using a known password and salt', function(done) {
      passwordHelper.hash('P@ssw0rd!', 'Salt', function(err, hash, salt) {
        if (err) throw err;

        should.exist(hash);
        hash.should.equal('1de6f322dcf2c8d864c4462fed39f41845a9152247ed3eccfc8562eb978ed067c5eb7d0b876c45ff4deeb8766138991b95cec44a75d83931bbb3937cba0f91fca65c7e531bd0bfa08ced0c88bebe2302406259f208cb219e1ff00e11b5b10cd30d01830ac63fafa1cfbd9009ed4c95ab19f508720cc13a50de09e9e4db2f3226');
        should.exist(salt);
        hash.should.be.a('string');
        salt.should.be.a('string');
        hash.should.not.equal('P@ssw0rd!');
        done();
      });
    });
    it('should return a hash and a salt from a plain string', function(done) {
      passwordHelper.hash('P@ssw0rd!', function(err, hash, salt) {
        if (err) throw err;

        should.exist(hash);
        should.exist(salt);
        hash.should.be.a('string');
        salt.should.be.a('string');
        hash.should.not.equal('P@ssw0rd!');
        done();
      });
    });

    it('should return the same hash if the password and salt ar the same', function(done) {
      passwordHelper.hash('P@ssw0rd!', function(err, hash, salt) {
        if (err) throw err;

        passwordHelper.hash('P@ssw0rd!', salt, function(err, hashWithSalt) {
          if (err) throw err;

          should.exist(hash);
          hash.should.be.a('string');
          hash.should.not.equal('P@ssw0rd!');
          hash.should.equal(hashWithSalt);
          done();
        });
      });
    });
  });

  describe('#verify() - compare a password with a hash', function() {
    it('should return true if the password matches the hash', function(done) {
      passwordHelper.hash('P@ssw0rd!', function(err, hash, salt) {
        if (err) throw err;

        passwordHelper.verify('P@ssw0rd!', hash, salt, function(err, result) {
          if (err) throw err;

          should.exist(result);
          result.should.be.a('boolean');
          result.should.equal(true);
          done();
        });
      });
    });

    it('should return false if the password does not matches the hash', function(done) {
      passwordHelper.hash('P@ssw0rd!', function(err, hash, salt) {
        if (err) throw err;

        passwordHelper.verify('password!', hash, salt, function(err, result) {
          if (err) throw err;

          should.exist(result);
          result.should.be.a('boolean');
          result.should.equal(false);
          done();
        });
      });
    });
  });
});
